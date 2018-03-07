#!/usr/bin/perl

=head1 NAME

Locationlogs

=cut

=head1 DESCRIPTION

unit test for Locationlogs

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

use Test::More tests => 14;
use Test::Mojo;

#This test will running last
use Test::NoWarnings;

my $t = Test::Mojo->new('pf::UnifiedApi');
my $test_mac = sprintf(
    "ff:ff:%02x:%02x:%02x:%02x",
    unpack("C4", pack("N", $$))
);

my $test_user = "test_user_$$";

$t->post_ok('/api/v1/users/' => json => {pid => $test_user})
  ->status_is(201)
  ->header_is('Location' => "/api/v1/user/$test_user");

my $location = $t->tx->res->headers->location;

$t->get_ok($location)
  ->status_is(200);

$t->post_ok("$location/nodes" => json => { mac => $test_mac } )
  ->status_is(201)
  ->header_is( 'Location' => "/api/v1/user/$test_user/node/$test_mac" );

$location = $t->tx->res->headers->location;

$t->post_ok("$location/locationlogs" => json => {})
  ->status_is(201)
  ->header_like('Location' => qr#^\Q$location\E/locationlog/[^/]+$#);

$location = $t->tx->res->headers->location;

$t->get_ok($location)
  ->status_is(200);


=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2018 Inverse inc.

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
