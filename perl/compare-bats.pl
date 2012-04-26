#!/usr/bin/perl -w

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use strict;
use Switch;
use Getopt::Long;
use warnings;

my $verbose = 0;
my $nofiltering = 0;
my %messageTypes = ();
my $unit = -1;

sub compareHeader
{
    my ($orig, $new) = @_;
    
    if ( $nofiltering && length($orig) == length($new) )
    {
        return ($orig eq $new);
    }
    else
    {
        my @newArray = split(//, $new);
        
        # assume the original is shorter
        foreach(split(//, substr($orig, 0, 8)))
        {
            if (ord($_) != ord($newArray[0]) )
            {
                return 0;
            }
            
            shift(@newArray);
        }
    }
    
    return 1;
}

sub compareMessages
{
    my ($orig, $new) = @_;

    if ( length($orig) != length($new) )
    {
        return 0;
    }
    
    my @newArray = split(//, $new);

    foreach(split(//, $orig))
    {
        if (ord($_) != ord($newArray[0]) )
        {
            return 0;
        }
        
        shift(@newArray);
    }
    
    return 1;
}

sub getMessageLength
{
    my ($buf) = @_;
    
    return ord(substr($buf, 0, 1));
}

sub getMessageType
{
    my ($buf) = @_;
    
    return substr($buf, 1, 1);
}

sub logMessage
{
    my ($type) = @_;
    
    if ( ! exists($messageTypes{$type}) )
    {
        $messageTypes{$type} = 1;
    }
    else
    {
        $messageTypes{$type}++;
    }
}

sub comparePayload
{
    my ($orig, $new, $newCount) = @_;
    
    my $origRemaining = $orig;
    my $dumpRemaining = $new;
    my $messagesInDump = 0;
    
    my $dumpMessage = substr($dumpRemaining, 0, getMessageLength($dumpRemaining));
    
    while ( length($origRemaining) != 0 )
    {
        if ( getMessageLength($origRemaining) == 0 )
        {
            die 'Invalid length found in original message';
        }
        
        my $origMessage = substr($origRemaining, 0, getMessageLength($origRemaining));
        
        if ( compareMessages($origMessage, $dumpMessage) )
        {
            if ( getMessageLength($dumpRemaining) > length($dumpRemaining) )
            {
                return 0;
            }
            
            logMessage(getMessageType($dumpMessage));
            $dumpRemaining = substr($dumpRemaining, getMessageLength($dumpRemaining));
            $dumpMessage = substr($dumpRemaining, 0, getMessageLength($dumpRemaining));
            
            $messagesInDump++;
        }
        
        $origRemaining = substr($origRemaining, getMessageLength($origRemaining));
    }
    
    if ( length($dumpRemaining) != 0 )
    {
        print "Unmatched messages in dump\n";
        
        return 0;
    }
    
    if ( $messagesInDump != $newCount )
    {
        printf "The new count was not set correctly expected %d but found %d messages!\n", $newCount, $messagesInDump;
        
        return 0;
    }
    
    return 1;
}

sub getHeaderFromPcap
{
    my ($buf) = @_;
    
    return substr($buf, 0, 8);
}

sub getMessagesFromPcap
{
    my ($buf) = @_;
    
    return substr($buf, 8);
}

sub getHeaderFromDump
{
    # we assume a dump is at least head swapped.
    my ($buf) = @_;
    
    return substr($buf, -16);
}

sub getMessagesFromDump
{
    # we assume a dump is at least head swapped.
    my ($buf) = @_;
    
    return substr($buf, 0, length($buf)-16);
}

sub getSequence
{
    my ( $bytes ) = @_;
    
    my $seq = substr($bytes, 4, 4);
    
    return unpack "L", $seq;
}

sub getNewCount
{
    my ( $head ) = @_;
    
    return ord(substr($head, 8, 1));
}

sub getUnit
{
    my ($head) = @_;
    
    return ord(substr($head, 3, 1));
}

my $count = 0;
my $dumpCount = -1;
my $buffer = "";
my $readNextDumpPacket = 1;
my $dumplen = 0;
my $payload = "";
my $dumpHeader = "";
my $dumpMessages = "";
my $dumpPacketSeq = 0;

sub readFiltered
{
    my ($count) = @_;
    
    if ( $readNextDumpPacket )
    {
        my $mid;
        
        $dumpCount++;
        
        if ( read(FILE, $buffer, 2) == 0 )
        {
            die 'No more data in dump file. Compared ' . ($count - 1) . ' (' . $dumpCount . ')' . ' packets.';
        }
        
        $dumplen = unpack ( "S", $buffer );
        
        if ( $dumplen < 16 )
        {
            die 'Packet ' . $count . ' (' . $dumpCount . ')' . ' is too short: ' . $dumplen;
        }
        
        read(FILE, $mid, 1);
    
        read(FILE, $payload, $dumplen);
        
        $dumpHeader = getHeaderFromDump($payload);
        
        $dumpMessages = getMessagesFromDump($payload);
        
        $dumpPacketSeq = getSequence($dumpHeader);
        
        $readNextDumpPacket = 0;
    }
}

sub comparePacket
{
    my ($origHeader, $origMessages, $count) = @_;
    
    my $origSequence = getSequence($origHeader);
    
    if ( $unit == -1 || $unit == getUnit($origHeader) )
    {
        if ( $origSequence == $dumpPacketSeq )
        {
            my $newCount = getNewCount($dumpHeader);
            
            $readNextDumpPacket = 1;
            
            if ( compareHeader($origHeader, $dumpHeader) == 0 )
            {
                die 'Packet headers do not match for packet ' . $count . ' (' . $dumpCount . ')';
            }
            
            if ( $nofiltering )
            {
                if ( $origMessages ne $dumpMessages )
                {
                    die 'Messages for packet ' . $count . ' (' . $dumpCount . ') do not match';
                }
            }
            elsif ( comparePayload($origMessages, $dumpMessages, $newCount) == 0 )
            {           
                die 'Messages for packet ' . $count . ' (' . $dumpCount . ') do not match or original contained a corrupt packet';
            }
        }
        elsif ( $nofiltering )
        {
            die 'Sequence numbers for packet ' . $count . ' (' . $dumpCount . ') do not match ' . $origSequence . ':' . $dumpPacketSeq;
        }
    }
}

sub processpacket
{
    my ($user_data, $header, $packet) = @_;
    my $pcapHeader = "";
    my $pcapMessages = "";
    
    readFiltered($count);
    
    #   Strip ethernet encapsulation of captured packet 
    my $ether_data = NetPacket::Ethernet::strip($packet);
    my $ip_obj = NetPacket::IP->decode($ether_data);
    my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
    
    $pcapHeader = getHeaderFromPcap($udp_obj->{data});
    
    $pcapMessages = getMessagesFromPcap($udp_obj->{data});
    
    comparePacket($pcapHeader, $pcapMessages, $count);
   
    $count++;
}

my $orig = "";
my $filtered = "";

Getopt::Long::Configure ('bundling');
GetOptions ('o|orig=s' => \$orig, 
            'f|filtered=s' => \$filtered,
            'n|no-filtering' => \$nofiltering,
            'v|verbose' => \$verbose,
            'u|unit=s' => \$unit);

if ( $orig eq "" or $filtered eq "" )
{
    die 'Missing required arguments';
}

if ( substr($filtered, -4) eq ".pcap" )
{
    die 'filtered file must be a dump file';
}

open(FILE, "<$filtered") or die "cannot open dump file " . $filtered . ": $!";

binmode(FILE);

if ( $orig eq "-" or substr($orig, -4) eq ".pcap" )
{
    my $object;
    my $err;

    if ( $verbose )
    {
        print 'Comparing pcap file ' . $orig . ' with dump file ' . $filtered . "\n";
    }
            
    $object = Net::Pcap::pcap_open_offline($orig, \$err);

    unless (defined $object)
    {
        die 'Unable to open packet capture ', $err;
    }

    Net::Pcap::pcap_loop($object, -1, \&processpacket, '') || die 'Unable to read packet';

    Net::Pcap::pcap_close($object);
    
    print 'Finished comparing. pcap = ' . $count . ', dump = (' . $dumpCount . ')\n';
    
    if ( read(FILE, $buffer, 2) != 0 )
    {
        die 'The filtered file has not been fully processed!';
    }
}
else
{
    if ( $verbose )
    {
        print 'Comparing dump file ' . $orig . ' with dump file ' . $filtered . "\n";
    }
    
    open(ORIGFILE, "<$orig") or die "cannot open dump file " . $orig . ": $!";

    binmode(ORIGFILE);
    
    my $count = 0;
    my $origbuffer = "";

    while (read(ORIGFILE, $origbuffer, 2) != 0)
    {
        my $len = 0;
        my $mid = "";
        my $origPayload = "";
        my $origHeader = "";
        my $origMessages = "";
        
        $len = unpack ( "S", $origbuffer );
              
        read(ORIGFILE, $mid, 1);
                
        read(ORIGFILE, $origPayload, $len);
        
        readFiltered($count);
        
        $origHeader = getHeaderFromDump($origPayload);
    
        $origMessages = getMessagesFromDump($origPayload);
        
        comparePacket($origHeader, $origMessages, $count);
        
        $count++;
    }
    
    close(ORIGFILE);
    
    print 'Finished comparing. orig = ' . $count . ', dump = (' . ($dumpCount+1) . ")\n";
}

close(FILE);

if ( $verbose )
{
    my $key;
    my $value;
    
    while (($key, $value) = each %messageTypes)
    {
        printf "%#-8x = %16d\n", ord($key), $messageTypes{$key};
    }
}


