#!/usr/bin/perl -w

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use strict;
use Switch;

sub isPrintable
{
    my ( $val ) = @_;
    
    return ( 0x20 <= $val && $val <= 0x7E );
}

sub ChangeByteOrder
{
    my ( $bytes ) = @_;
    
    my @a = split(//, $bytes);
    my $ret = "";
    
    foreach(@a)
    {
        $ret = $_ . $ret;
    }
    
    return $ret;
}

sub printHeader
{
    my ( $bytes ) = @_;
    my $length    = substr($bytes, 0, 2);
    my $count     = substr($bytes, 2, 1);
    my $unit      = substr($bytes, 3, 1);
    my $seq       = substr($bytes, 4, 4);
    
    print "\nBATS Packet Header\n";
    print "-----------------\n";
    printf("Length:      %d\n", unpack "S", $length);
    printf("Count:       %d\n", ord($count));
    printf("Unit:        %d\n", ord($unit));
    printf("Sequence:    %d\n", unpack "L", $seq);
}

sub printPayload
{
    my ( $bytes ) = @_;
    my $headerSize = 20;
    
    $bytes = substr($bytes, $headerSize);
    
    my $msgtype = ChangeByteOrder substr($bytes, 2, 2);   
    my $numBodies = ord substr($bytes, 14, 1);

    switch ( $msgtype )
    {
        case [230..232]
        {            
            my $i;
            
            for ($i = 0; $i < $numBodies; $i++ )
            {
                my $msgsize = unpack "S", ChangeByteOrder substr($bytes, 0, 2);
                my $securityIndex = unpack "S", ChangeByteOrder substr($bytes, 2, 2);
                
                printf("--->Msg:            %d\n", $i);
                printf("--->MsgSize:        %d\n", $msgsize);
                printf("--->SecurityIndex:  %d\n", $securityIndex);
                
                $bytes = substr($bytes, $msgsize);
            }
        }
    }
}

sub dumpHex
{
    my ( $payload ) = @_;
    
    printf "%10s", "offset  ";

    foreach ( 0 .. 0xF )
    {
        printf "%.2x", $_;
        print " ";
        if ( ($_ + 1) % 4 == 0 )
        {
            print " ";
        }
    }

    print "\n" . " ";

    foreach ( 2 .. 9 )
    {
        print "-";
    }

    foreach ( 0 .. 0xF )
    {
        print "---";
        if ( ($_ + 1) % 4 == 0 && $_ != 0xF )
        {
            print "-";
        }
    }

    print "\n";

    my $i = 0;
    my $chars = "";

    printf "%.8x  ", $i;
   
    foreach (split(//, $payload))
    {
        printf("%.2x ", ord($_));
        
        $i ++;
        
        if ( isPrintable(ord($_)) )
        {
            $chars = $chars . chr(ord($_));
        }
        else
        {
            $chars = $chars . '.';
        }
        
        if ( $i % 16 == 0 )
        {
            print "  " . $chars;
            $chars = "";
            print "\n";
            printf "%.8x  ", $i;
        }
        else
        {
            if ( $i % 4 == 0 )
            {
                print " ";
            }
        }
    }

    if ( $i % 16 != 0 )
    {
        my $ycord = ($i % 16);
        foreach ( $ycord .. 15 )
        {
            print "   ";
            
            if ( ($_ + 1) % 4 == 0 )
            {
                print " ";
            }
        }
        
        print " " . $chars;
    }

    print "\n\n";
}

my $count = 0;

sub processpacket
{
    my ($user_data, $header, $packet) = @_;
    
    #   Strip ethernet encapsulation of captured packet 
    my $ether_data = NetPacket::Ethernet::strip($packet);
    
    my $ip_obj = NetPacket::IP->decode($ether_data);
    
    my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
    
    print "\nMessage: " . $count . "\n";
    print "Length: " . length($udp_obj->{data}) . "\n";
    printHeader($udp_obj->{data});
    #printPayload($udp_obj->{data});
    print "\n";
    dumpHex $udp_obj->{data};
    
    $count++;
}

foreach (@ARGV)
{
    my $object;
    my $err;
    
    $object = Net::Pcap::pcap_open_offline($_, \$err);
    
    unless (defined $object)
    {
        die 'Unable to open packet capture ', $err;
    }
    
    Net::Pcap::pcap_loop($object, -1, \&processpacket, '') || die 'Unable to read packet';
    
    Net::Pcap::pcap_close($object);
}



