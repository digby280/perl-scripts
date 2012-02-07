#!/usr/bin/perl -w

sub isPrintable
{
    my ( $val ) = @_;
    
    return ( 0x20 <= $val && $val <= 0x7E );
}

sub reverseBytes
{
    my ( $bytes ) = @_;
    my $ret = "";
    
    foreach (split(//, $bytes))
    {
        $ret = $_ . $ret;
    }
    
    return $ret;
}

sub getField
{
    my ( $bytes, $count, $offset) = @_;
    
    my @head = split(//, $bytes);
    
    my $ret = "";
    my $i = 0;
    
    for ( $i = 0; $i < $count; $i++ )
    {
        $ret = $head[$i + $offset] . $ret;
    }
    
    return $ret;
}

sub printHeader
{
    my ( $bytes ) = @_;
    
    my $msgsize = getField($bytes, 2, 0);
       
    my $msgtype = getField($bytes, 2, 2);
    
    my $seq     = getField($bytes, 4, 4);
    
    my $sendtime = getField($bytes, 4, 8);
    
    my $productID = getField($bytes, 1, 12);
    
    my $retransflag = getField($bytes, 1, 13);
    
    my $numBodies = getField($bytes, 1, 14);
    
    my $filler = getField($bytes, 1, 15);
    
    my $dropcount = getField($bytes, 4, 16);
    
    my $lastseq = getField($bytes, 4, 20);
    
    print "\nARCA Header\n";
    print "-----------\n";
    printf("MsgSize:     %d\n", unpack "S", $msgsize);
    printf("MsgType:     %d\n", unpack "S", $msgtype);
    printf("MsgSeq:      %d\n", unpack "I", $seq);
    printf("SendTime:    %d\n", unpack "I", $sendtime);
    
    printf("ProductID:   %d\n", ord $productID);
    printf("RetransFlag: %d\n", ord $retransflag);
    printf("NumBodies:   %d\n", ord $numBodies);
    printf("Filler:      %d\n", ord $filler);
    
    printf("DropCount:   %d\n", unpack "I", $dropcount);
    printf("LastSeq:     %d\n", unpack "I", $lastseq);
}

sub getHeader
{
    my ( $bytes ) = @_;
    
    my @payload = split(//, $bytes);
    my $headerSize = 16 + 8;
    my $payloadLength = @payload;
    
    my $offset = $payloadLength - $headerSize;
    
    my $i;
    my $ret = "";
    
    for ( $i = $offset; $i < $payloadLength; $i++ )
    {
        $ret = $ret . $payload[$i];
    }
    
    return $ret;
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


