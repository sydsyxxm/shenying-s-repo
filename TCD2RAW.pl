#!/usr/bin/perl -w
# Read the output of 'tcpdump -x' and convert back to the
# original tcd-native (network-ordered) format.
# 12/17/02  SPM

use POSIX qw(mktime);


### Globals
$Input = STDIN;
$Output = STDOUT;
$timeStamp = "";
$timeStampDay = 0;
$timeStampMonth = 0;
$timeStampYear = 0;
$fromAddr = "";
$toAddr = "";
$DebugLevel = 0;
$snapLength = 1514;
@tcpPayload = ();

$Usage = "$0 [-i input_file] [-o output_file] [-v debug_volume]\n" .
    "\t[-d date]\n".
    "\tDefaults to read from standard in, writing to standard out";


# constants
$BogusSourceMAC = pack("C6", 4, 2, 4, 2, 4, 2);
$BogusDestMAC = pack("C6", 1, 3, 1, 3, 1, 3);
$EtherHeaderLength = 14;
# taken from pcap source
$TCPDUMP_MAGIC =  0xa1b2c3d4;
$DLT_EN10MB = 1;
$LINKTYPE_ETHERNET = $DLT_EN10MB;
# Ether and IP constants
$ETHERTYPE_IP = 0x0800;
$ETHERTYPE_MAX = 0xFFFF;


# $testVal = 0x12345678;
# $test = (pack("C4", $testVal) eq pack("N", $testVal));


################################################################
#
#  initGlobals - Set up some global vals.  Can be overridden
#                by command line, below
#
################################################################

sub initGlobals {

    ($junk, $junk, $junk, $timeStampDay,
     $timeStampMonth, $timeStampYear, $junk, $junk, $junk) = localtime;
    
#     print STDERR "Test result = ", (($test == 1) ? "true" : "false"), "\n";
#     print STDERR join(" ", map { sprintf "%#02x", $_ }
#                       unpack("C*",pack("L",0x12345678))), "\n";

}


################################################################
#
#  readArgs - Populate the above
#
################################################################

sub readArgs {

    while ($#ARGV > -1) {
        my $arg = shift @ARGV;
        my $file = "";
        if ($arg =~ /^-v/) {
            $DebugLevel = int(shift @ARGV);
        }
        elsif ($arg =~ /^-i/) {
            $file = shift @ARGV;
            open(INPUT, "<$file") or
                die "Unable to open $file for reading, $!\n";
            $Input = \*INPUT;
        }
        elsif ($arg =~ /^-o/) {
            $file = shift @ARGV;
            open(OUTPUT, ">$file") or
                die "Unable to open $file for writing, $!\n";
            $Output = \*OUTPUT;
        }
        elsif ($arg =~ /^-d/) {
            # This'll be a stinker.  Parse the arg
            # looking for a date specifier
            my @date = split(m%[/:\s]%, shift @ARGV);
            if ($#date != 2) {
                print "Unable to parse date arg, try mm/dd/yy\n";
                print $Usage, "\n";
                exit 2;
            }
            $timeStampMonth = $date[0] - 1;
            $timeStampDay   = $date[1];
            # year garbage
            if ($date[2] > 1899) {
                $timeStampYear  = $date[2] - 1900;
            }
            elsif ($date[2] > 50) {
                $timeStampYear = $date[2];
            }
            else {
                $timeStampYear = $date[2] + 100;
            }
        }
        else {
            print $Usage, "\n";
            exit 1;
        }
    }

}


################################################################
#
#  etherType - Strip off the first char of the argument, return
#              it as an integer =8-p
#
################################################################

sub etherType {

    my $input = shift;
    return int(substr($input, 0, 1));

}


################################################################
#
#  packetLength - Calculate packet width
#
################################################################

sub packetLength {
    my @words = @_;
    my $total = 0;
    foreach $bits (@words) {
        $total += int((length($bits)) / 2);
    }
    $total += $EtherHeaderLength;

    if ($DebugLevel > 2) {
        print STDERR "Packet length = $total\n";
    }
    return $total;

}


################################################################
#
#  writePacketHeader - writes the timestamp (relative to
#                      today, since we lose the date in the
#                      tcd file), the captured length, and
#                      the packet length
#                      Also write the bogus ethernet header
#
################################################################

sub writePacketHeader {

    my $length = shift;
    my $etherType = shift;
    
    my @timeParts = split(/[:\.]/, $timeStamp);
    my $first = mktime($timeParts[2], # seconds from timestamp
                       $timeParts[1], # minutes
                       $timeParts[0], # hours
                       $timeStampDay,
                       $timeStampMonth,
                       $timeStampYear);
    print $Output pack("N", $first);
    my $minsec=sprintf ("%-6s",$timeParts[3]);
    $minsec =~ s/ /0/g;
    print $Output pack("N", $minsec);
    # This appears to be the wrong order.  Don't understand why
    print $Output pack("N2", $length, $snapLength);
    print $Output $BogusSourceMAC, $BogusDestMAC;
    # This could go horribly wrong
    print $Output pack("n", (($etherType == 4) ? $ETHERTYPE_IP :
                             $ETHERTYPE_MAX));
}


################################################################
#
#  writeFileHeader - Put the inital stuff to disk.  Looks like:
# struct pcap_file_header {
#	bpf_u_int32 magic;
#	u_short version_major;
#	u_short version_minor;
#	bpf_int32 thiszone;	/* gmt to local correction */
#	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
#	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
#	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
#
#
################################################################

sub writeFileHeader {

    # We're gonna write these as-is, hard-coded
    print $Output pack("N", $TCPDUMP_MAGIC);
    print $Output pack("n2", 2, 4);
    print $Output pack("N4",
                       0, # this is what's written in current files
                       0, # ????
                       $snapLength, # Why not
                       $LINKTYPE_ETHERNET);
}


################################################################
#
#  writePacket - Takes the contents of tcpPayload, timeStamp,
#                fromAddr and toAddr, dumps the network-order
#                bytes to Output
#
################################################################

sub writePacket {

    return if ($#tcpPayload == -1);  # Nobody home
    writePacketHeader(packetLength(@tcpPayload),
                      etherType($tcpPayload[0]));
    
    foreach $word (@tcpPayload) {
        if (length($word) < 4) {
            print $Output pack("C", hex($word));
        }
        else {
            print $Output pack("n", hex($word));
        }
        # print $Output pack("C2", hex(substr($word, 0, 2)),
                           # hex(substr($word, 2, 2)));
        #print $Output pack "h2", hex($word);
        if ($DebugLevel > 2) {
            print STDERR "Wrote $word\n";
        }
    }

    @tcpPayload = ();
}


################################################################
#
#  parseFile - Read the TCD input and pop out a raw file
#
################################################################

sub parseFile {

    writeFileHeader();
    
    while (<$Input>) {
        chomp;
        if (/^([\d:.]+).+([\d.]+).+([\d.]+)/) {
            # found another packet
            writePacket();
            $timeStamp = $1;
            $fromAddr = $2;
            $toAddr = $3;
        }
        elsif (/^\s+\w/) {
            push @tcpPayload, split;
        }
        elsif ($DebugLevel > 1) {
            print STDERR "Unknown line \"$_\"\n";
        }
    }
    writePacket(); # Clean up the last one
    
}



### MAIN

initGlobals();
readArgs();
parseFile();

0;
