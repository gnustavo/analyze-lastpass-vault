#!/usr/bin/env perl

use 5.016;
use common::sense;
use Text::CSV qw(csv);
use XML::LibXML::Simple qw(XMLin);

@ARGV == 1 or die "Usage: $0 INPUT";
my $vaultfile = shift;

my $data = XMLin(
    $vaultfile,
    ForceArray => 1,
    KeepRoot => 1,
);

my @results;

while (my ($name, $account) = each $data->{response}[0]{accounts}[0]{account}->%*) {
    my %result = (
        Name          => $name,
        URL           => $account->{url},
        ID            => $account->{id},
        Group         => $account->{group},
        Extra         => $account->{extra},
        IsBookmark    => $account->{isbookmark},
        NeverAutofill => $account->{never_autofill},
        LastTouch     => $account->{last_touch},
        LastModified  => $account->{last_modified},
        LaunchCount   => $account->{launch_count},
        UserName      => $account->{login}[0]{u},
        Password      => $account->{login}[0]{p},
    );

    # Convert the hexadecimal values to text/ASCII
    $result{URL} = join('', map {chr eval "0x$_"} ($result{URL} =~ /([0-9a-f]{2})/g));

    # Identify values encrypted with ECB
    foreach my $attr (qw/Name Extra UserName Password Group/) {
        if (! $result{$attr}) {
            $result{$attr} = 'Blank';
        } elsif ($result{$attr} =~ /^!/) {
            $result{$attr} = 'OK';
        } else {
            $result{$attr} = 'WARNING: Encrypted with ECB!';
        }
    }

    # Convert dates to human readable
    foreach my $attr (qw/LastTouch LastModified/) {
        my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = gmtime($result{$attr});

        $result{$attr} = sprintf("%04d-%02d-%02d %02d:%02d:%02d [UTC]",
                                 $year + 1900,
                                 $mon + 1,
                                 $mday,
                                 $hour,
                                 $min,
                                 $sec,
                             );
    }

    push @results, \%result;
}

csv(
    in  => \@results,
    out => *STDOUT,
    headers => [sort keys $results[0]->%*],
    enc => ':encoding(utf-8)',
);

__END__
=encoding utf8

=head1 NAME

analize-lastpass-vault.pl - Analyze the contents of your LastPass Vault

=head1 SYNOPSIS

analize-lastpass-vault.pl <VAULT_FILE>

=head1 DESCRIPTION

Scan the contents of your LastPass Vault (XML), decode the URLs, decode
timestamps, and warn on any values encrypted with ECB.

This is a simple translation into Perl of the original
F<Analyze-LastPassVault.ps1> Powershell script written by Rob Woodruff with help
from ChatGPT and Steve Gibson More information and updates can be found at
https://github.com/FuLoRi/Analyze-LastPassVaultGUI

This Perl script uses two non-core modules (C<Text::CSV> and
C<XML::LibXML::Simple>) which can be installed like this on Debian derived Linux
distributions, such as Ubuntu:

  sudo apt-get install libtext-csv-perl libxml-libxml-simple-perl

In order to extract your LastPass Vault in XML format, do the following:

=over

=item 1. Open Chrome or Edge. Login to LastPass so that you're looking at your vault.

=item 2. Press F12 to open the developer tools. Select the "Console" tab to move to that view. You'll have a cursor.

=item 3. Paste the following JavaScript query into the console and press "Enter". Your page will fill with a large XML dump.

  fetch("https://lastpass.com/getaccts.php", {method: "POST"})
    .then(response => response.text())
    .then(text => console.log(text.replace(/>/g, ">\n")));

=item 4. Look carefully at the bottom of the page for the "Show More" and "Copy" options.

=item 5. Click "Copy" to copy all of that query response data onto the clipboard.

=item 6. Save your clipboard to a file, e.g. F<vault.xml>.

=item 7. Run this script like this to analyze the file you saved and to produce a CSV report in a file called F<vault.csv>:

  ./analyze-lastpass-vault.pl vault.xml >vault.csv

=item 8. Open the output file to see the decoded URLs and a brief analysis of each encrypted field.
Note: "OK" means it's encrypted with CBC, "Blank" means the field is empty, and a warning means it's encrypted with ECB.

=back

=head1 SEE ALSO

=over

=item * The original L<Analyze-LastPassVaultGUI.ps1|https://github.com/FuLoRi/Analyze-LastPassVaultGUI> Powershell script.

=item * Security Now's episode 904 (L<Leaving LastPass|https://www.grc.com/sn/sn-904.htm>)

Where Steve Gibson explains the LastPass snafu.

=item * Security Now's episode 905 (L<1|https://www.grc.com/sn/sn-904.htm>)

Where Steve Gibson explains how to use and the purpose of this script, in
addition to the dangers of having your vault exposed.

=back

=head1 COPYRIGHT

Copyright 2023 Gustavo Chaves <gnustavo@cpan.org>.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Gustavo Chaves <gnustavo@cpan.org>
