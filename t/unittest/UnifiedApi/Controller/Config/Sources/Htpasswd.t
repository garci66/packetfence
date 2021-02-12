#!/usr/bin/perl

=head1 NAME

Htpasswd

=head1 DESCRIPTION

unit test for Htpasswd

=cut

use strict;
use warnings;
#
use lib '/usr/local/pf/lib';

BEGIN {
    #include test libs
    use lib qw(/usr/local/pf/t);
    #Module for overriding configuration paths
    use setup_test_config;
}

use Test::More tests => 7;

#This test will running last
use Test::NoWarnings;
use Test::Mojo;

my $t = Test::Mojo->new('pf::UnifiedApi');
use pf::ConfigStore::Source;
use Utils;
my ($fh, $filename) = Utils::tempfileForConfigStore("pf::ConfigStore::Source");

my $collection_base_url = '/api/v1/config/sources';

my $base_url = '/api/v1/config/source';

#This is the second test
$t->post_ok("$collection_base_url/test" =>
    json => {
        type => 'Htpasswd',
        id   => 'test',
        path => '/usr/local/pf/t/data/htpasswd.conf',
        description => "Test",
    }
  )
  ->status_is(405)
  ->json_has('/errors');

$t->get_ok("$base_url/htpasswd1")
  ->status_is(200)
  ->json_is('/item/class' => 'internal');

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2021 Inverse inc.

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

