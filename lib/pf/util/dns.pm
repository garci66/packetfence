package pf::util::dns;

=head1 NAME

pf::util::dns

=cut

=head1 DESCRIPTION

Util functions for DNS

=cut

use strict;
use warnings;

use pf::constants;
use pfconfig::cached_hash;

tie our %passthroughs, 'pfconfig::cached_hash', 'resource::passthroughs';
tie our %isolation_passthroughs, 'pfconfig::cached_hash', 'resource::isolation_passthroughs';

=head2 matches_passthrough

Whether or not a domain matches a configured DNS passthrough

Returns 2 values
- Whether or not it matched
- List of ports that should be opened for this domain

=cut

sub matches_passthrough {
    my ($domain,$zone) = @_;
    # undef domains are not passthroughs
    return ($FALSE, []) unless(defined($domain));

    # Check for non-wildcard passthroughs
    my $normal = '$'.$zone.'{normal}{$domain}';
    $normal = eval($normal);
    if(defined($normal)) {
        return ($TRUE, $normal);
    }

    # check if its a sub-domain of a wildcard domain
    my @parts = split(/\./, $domain);
    my $last_element = scalar(@parts)-1;
    for (my $i=$last_element; $i>0; $i--) {
        my @sub_parts = @parts[$i..$last_element];
        my $domain = join('.', @sub_parts);
        my $wildcard = '$'.$zone.'{wildcard}{$domain}';
        $wildcard = eval($wildcard);
        if(defined($wildcard)) {
            return ($TRUE, $wildcard);
        }
    }

    # Fallback to not a passthrough
    return ($FALSE, []);
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

Minor parts of this file may have been contributed. See CREDITS.

=head1 COPYRIGHT

Copyright (C) 2005-2017 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
