package pf::violation_config;

=head1 NAME

pf::violation_config

=cut

=head1 DESCRIPTION

pf::violation_config

=cut

use strict;
use warnings;
use Log::Log4perl qw(get_logger);
use Try::Tiny;

use pf::config;
use pf::trigger qw(trigger_delete_all parse_triggers);
use pf::class qw(class_merge);

our (%Violation_Config, $cached_violations_config);

BEGIN {
    use Exporter ();
    our ( @ISA, @EXPORT );
    @ISA = qw(Exporter);
    # Categorized by feature, pay attention when modifying
    @EXPORT = qw(%Violation_Config $cached_violations_config readViolationConfigFile);
}

sub readViolationConfigFile {
    my $logger = get_logger();
    unless ($cached_violations_config) {
        $cached_violations_config = pf::config::cached->new(
                -file => $violations_config_file,
                -allowempty => 1,
        );
        if ( scalar(@Config::IniFiles::errors) ) {
            $logger->error( "Error reading $violations_config_file " .  join( "\n", @Config::IniFiles::errors ) . "\n" );
            return 0;
        }
        my $callback = sub {
            my ($config) = @_;
            $config->toHash(\%Violation_Config);
            $config->cleanupWhitespace(\%Violation_Config);
            trigger_delete_all();
            foreach my $violation ( keys %Violation_Config ) {

                # parse triggers if they exist
                my $triggers_ref = [];
                if ( defined $Violation_Config{$violation}{'trigger'} ) {
                    try {
                        $triggers_ref = parse_triggers($Violation_Config{$violation}{'trigger'});
                    } catch {
                        $logger->warn("Violation $violation is ignored: $_");
                        $triggers_ref = [];
                    };
                }

                # parse grace, try to understand trailing signs, and convert back to seconds
                if ( defined $Violation_Config{$violation}{'grace'} ) {
                    $Violation_Config{$violation}{'grace'} = normalize_time($Violation_Config{$violation}{'grace'});
                }

                if ( defined $Violation_Config{$violation}{'window'} && $Violation_Config{$violation}{'window'} ne "dynamic" ) {
                    $Violation_Config{$violation}{'window'} = normalize_time($Violation_Config{$violation}{'window'});
                }

                # be careful of the way parameters are passed, whitelists, actions and triggers are expected at the end
                class_merge(
                    $violation,
                    $Violation_Config{$violation}{'desc'} || '',
                    $Violation_Config{$violation}{'auto_enable'},
                    $Violation_Config{$violation}{'max_enable'},
                    $Violation_Config{$violation}{'grace'},
                    $Violation_Config{$violation}{'window'},
                    $Violation_Config{$violation}{'vclose'},
                    $Violation_Config{$violation}{'priority'},
                    $Violation_Config{$violation}{'template'},
                    $Violation_Config{$violation}{'max_enable_url'},
                    $Violation_Config{$violation}{'redirect_url'},
                    $Violation_Config{$violation}{'button_text'},
                    $Violation_Config{$violation}{'enabled'},
                    $Violation_Config{$violation}{'vlan'},
                    $Violation_Config{$violation}{'target_category'},
                    $Violation_Config{$violation}{'whitelisted_categories'} || '',
                    $Violation_Config{$violation}{'actions'},
                    $triggers_ref
                );
            }
        };
        $cached_violations_config->addReloadCallback($callback);
    } else {
        $cached_violations_config->ReadConfig();
    }
    return 1;
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

Minor parts of this file may have been contributed. See CREDITS.

=head1 COPYRIGHT

Copyright (C) 2005-2013 Inverse inc.

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

