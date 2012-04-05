#!/usr/bin/perl -w

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
    my $msgCount  = substr($bytes, 8, 1);
    my $dropcount = ChangeByteOrder (chr(0) . substr($bytes, 9, 3));
    my $expected  = ChangeByteOrder substr($bytes, 12, 8);
    
    print "\nBATS Packet Header\n";
    print "-----------------\n";
    printf("Length:      %d\n", unpack "S", $length);
    printf("Count:       %d\n", ord($count));
    printf("Unit:        %d\n", ord($unit));
    printf("Sequence:    %d\n", unpack "L", $seq);
    printf("NewCount:    %d\n", ord $msgCount);
    printf("DropCount:   %d\n", unpack "I", $dropcount);
    printf("Expected:    %llu\n", unpack "Q", $expected);
}

sub getHeader
{
    my ( $bytes ) = @_;
    
    my $headerSize = 8 + 4 + 20;
    
    return substr($bytes, -$headerSize);
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
        foreach ( ($i % 16) .. 15 )
        {
            print "   ";
            
            if ( $i % 4 == 0 )
            {
                print " ";
            }
        }
        
        print "  " . $chars;
    }

    print "\n\n";
}

foreach (@ARGV)
{
    my $buffer = "";

    open(FILE, "<$_") or die "cannot open dump file: $!";

    binmode(FILE); 

    my $count = 0;

    while (read(FILE, $buffer, 2) != 0)
    {
        my $len = 0;
        my $val = 0;
        my $mid = "";
        my $payload = "";
        
        $len = unpack ( "S", $buffer );
       
        print "Message: ". $count . "\n";
        printf ("Length: %d\n", $len);
        
        read(FILE, $mid, 1);
        
        printf ("Multicast ID: %d\n", ord($mid));
        
        read(FILE, $payload, $len);
        
        my $header = getHeader($payload);
        
        printHeader($header);
        
        print "\n";
        
        dumpHex $payload;
        
        $count++;
    }

    close(FILE);
}


