#!/usr/bin/perl

=head1 NAME

LDAPSource

=cut

=head1 DESCRIPTION

unit test for LDAPSource

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
use pf::authentication;

#This test will running last
use Test::NoWarnings;

my $source_id = 'LDAPCACHEMATCH';

my $source = getAuthenticationSource($source_id);

ok($source, "Got source id $source_id");

BAIL_OUT("Cannot get $source_id") unless $source;

my $rule = pf::Authentication::Rule->new(
    {
        id => "test1",
        class => $Rules::AUTH,
        match => $Rules::ANY,
        conditions => [],
    }
);

ok($source->is_rule_cacheable($rule), "No conditions is cachable");

$rule = pf::Authentication::Rule->new(
    {
        id => "test1",
        class => $Rules::AUTH,
        match => $Rules::ANY,
        conditions => [
            pf::Authentication::Condition->new(
                {
                    attribute => 'bob',
                    operator => $Conditions::IN_TIME_PERIOD,
                    value => time,
                }
            )
        ],
    }
);

ok(!$source->is_rule_cacheable($rule), "If one condition is a IN_TIME_PERIOD then fail");

$rule = pf::Authentication::Rule->new(
    {
        id => "test1",
        class => $Rules::AUTH,
        match => $Rules::ANY,
        conditions => [
            pf::Authentication::Condition->new(
                {
                    attribute => 'bob',
                    operator => $Conditions::IS_BEFORE,
                    value => time,
                }
            )
        ],
    }
);

ok(!$source->is_rule_cacheable($rule), "If one condition is a IS_BEFORE then fail");

$rule = pf::Authentication::Rule->new(
    {
        id => "test1",
        class => $Rules::AUTH,
        match => $Rules::ANY,
        conditions => [
            pf::Authentication::Condition->new(
                {
                    attribute => 'bob',
                    operator => $Conditions::IS_AFTER,
                    value => time,
                }
            )
        ],
    }
);

ok(!$source->is_rule_cacheable($rule), "If one condition is a IS_AFTER then fail");

$rule = pf::Authentication::Rule->new(
    {
        id => "test1",
        class => $Rules::AUTH,
        match => $Rules::ANY,
        conditions => [
            pf::Authentication::Condition->new(
                {
                    attribute => 'bob',
                    operator => $Conditions::STARTS,
                    value => 'bob',
                }
            )
        ],
    }
);

ok($source->is_rule_cacheable($rule), "Non date related is cachable");

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

