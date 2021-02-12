#!/usr/bin/perl

=head1 NAME

ConnectionProfiles

=cut

=head1 DESCRIPTION

unit test for ConnectionProfiles

=cut

use strict;
use warnings;
#
use lib '/usr/local/pf/lib';
our $dir;
BEGIN {
    #include test libs
    use lib qw(/usr/local/pf/t);
    use File::Temp qw(tempdir);
    #Module for overriding configuration paths
    use setup_test_config;
    $dir = tempdir( CLEANUP => 1 );
    $pf::file_paths::captiveportal_profile_templates_path = $dir;
}

use pf::ConfigStore::Profile;
use Utils;
my ($fh, $filename) = Utils::tempfileForConfigStore("pf::ConfigStore::Profile");

use Test::More tests => 36;
use Test::Mojo;
#This test will running last
use Test::NoWarnings;
my $t = Test::Mojo->new('pf::UnifiedApi');

my $collection_base_url = '/api/v1/config/connection_profiles';

my $base_url = '/api/v1/config/connection_profile';

$t->post_ok($collection_base_url => json => { id => 'test_audit', root_module => 'default_policy', advanced_filter => undef, filter => [ {type => 'ssid', match => 'bob'}], })
  ->status_is(201);

$t->put_ok("$base_url/test_audit/files/bob.html" => {} => "bob")
  ->status_is(200);

$t->get_ok($collection_base_url)
  ->status_is(200)
  ->json_is('/items/0/id', 'default');

my $items = $t->tx->res->json->{items};

$t->patch_ok("$base_url/default" => json => {sources => [qw(blackhole)]})
  ->status_is(200);

$t->patch_ok("$base_url/default" => json => {sources => [qw(blackhole htpasswd)]})
  ->status_is(422);

$t->patch_ok("$base_url/blackhole" => json => {sources => [qw(blackhole)]})
  ->status_is(200);

$t->patch_ok("$base_url/blackhole" => json => {sources => [qw(blackhole htpasswd)]})
  ->status_is(422);

$t->get_ok("$base_url/default")
  ->status_is(200)
  ->json_is('/item/id', 'default');

$t->post_ok($collection_base_url => json => {})
  ->status_is(422);

$t->post_ok($collection_base_url => json => {id => 'default'})
  ->status_is(409);

$t->post_ok($collection_base_url, {'Content-Type' => 'application/json'} => '{')
  ->status_is(400);

$t->patch_ok("$base_url/default" => json => {})
  ->status_is(200);

$t->put_ok("$base_url/default" => json => {})
  ->status_is(422);

$t->get_ok($collection_base_url)
  ->status_is(200);

my @names = reverse sort grep { $_ ne 'default' } map { $_->{id} } @$items;

$t->patch_ok("$collection_base_url/sort_items" => json => {items => \@names})
  ->status_is(200);

$t->get_ok($collection_base_url)
  ->status_is(200);

$items = $t->tx->res->json->{items};
my @new_names = map { $_->{id} } @$items;

is_deeply(\@new_names, ['default', @names], "Resorting");


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
