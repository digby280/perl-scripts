#!/usr/bin/perl -w

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use strict;
use Switch;
use Getopt::Long;
use warnings;

sub compareHeader
{
    my ($orig, $new) = @_;
    
    if ( length($orig) == length($new) )
    {
        return ($orig eq $new);
    }
    else
    {
        my @newArray = split(//, $new);
        # assume the original is shorter
        foreach(split(//, $orig))
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

sub comparePayload
{
    my ($orig, $new) = @_;
    
    if ( length($orig) == length($new) )
    {
        return ($orig eq $new);
    }
    else
    {
        my $origRemaining = $orig;
        my $dumpRemaining = $new;
        
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
                $dumpRemaining = substr($dumpRemaining, getMessageLength($dumpRemaining));
                $dumpMessage = substr($dumpRemaining, 0, getMessageLength($dumpRemaining));
            }
            
            $origRemaining = substr($origRemaining, getMessageLength($origRemaining));
        }
        
        if ( length($dumpRemaining) != 0 )
        {
            print 'Unmatched messages in dump\n';
            
            return 0;
        }
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

my $count = 0;
my $dumpCount = -1;
my $buffer = "";
my $readNextDumpPacket = 1;
my $dumplen = 0;
my $payload = "";
my $dumpHeader = "";
my $dumpMessages = "";
my $dumpPacketSeq = 0;
my $nofiltering = 0;
    
sub processpacket
{
    my ($user_data, $header, $packet) = @_;
    my $pcapHeader = "";
    my $pcapMessages = "";
    my $pcapPacketSequence = 0;
    
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
    
    #   Strip ethernet encapsulation of captured packet 
    my $ether_data = NetPacket::Ethernet::strip($packet);
    my $ip_obj = NetPacket::IP->decode($ether_data);
    my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
    
    $pcapHeader = getHeaderFromPcap($udp_obj->{data});
    
    $pcapPacketSequence = getSequence($pcapHeader);
    
    if ( $pcapPacketSequence == $dumpPacketSeq )
    {
        $readNextDumpPacket = 1;
        
        if ( compareHeader($pcapHeader, $dumpHeader) == 0 )
        {
            die 'Packet headers do not match for packet ' . $count . ' (' . $dumpCount . ')';
        }
        
        $pcapMessages = getMessagesFromPcap($udp_obj->{data});
        
        if ( $nofiltering )
        {
            if ( $pcapMessages ne $dumpMessages )
            {
                die 'Messages for packet ' . $count . ' (' . $dumpCount . ') do not match';
            }
        }
        elsif ( comparePayload($pcapMessages, $dumpMessages) == 0 )
        {
            die 'Messages for packet ' . $count . ' (' . $dumpCount . ') do not match';
        }
    }
    elsif ( $nofiltering )
    {
        die 'Sequence numbers for packet ' . $count . ' (' . $dumpCount . ') do not match';
    }
   
    $count++;
}

my $orig = "";
my $filtered = "";

Getopt::Long::Configure ('bundling');
GetOptions ('o|orig=s' => \$orig, 'f|filtered=s' => \$filtered, 'n|no-filtering' => \$nofiltering);

if ( $orig eq "" or $filtered eq "" )
{
    die 'Missing required arguments';
}

if ( substr($filtered, -4) eq ".pcap" )
{
    die 'filtered file must be a dump file';
}

if ( $orig eq "-" or substr($orig, -4) eq ".pcap" )
{
    my $object;
    my $err;
    
    open(FILE, "<$filtered") or die "cannot open dump file " . $filtered . ": $!";

    binmode(FILE);
    
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
    
    close(FILE);
}
else
{
    die 'comparing dump against dump is not currently supported ' . $orig;
}



