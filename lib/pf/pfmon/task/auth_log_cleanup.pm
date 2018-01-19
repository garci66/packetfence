package pf::pfmon::task::auth_log_cleanup;

=head1 NAME

pf::pfmon::task::auth_log_cleanup - class for pfmon task auth log cleanup

=cut

=head1 DESCRIPTION

pf::pfmon::task::auth_log_cleanup

=cut

use strict;
use warnings;
use Moose;
use pf::auth_log;
extends qw(pf::pfmon::task);

has 'batch' => ( is => 'rw');
has 'timeout' => ( is => 'rw', isa => 'PfInterval', coerce => 1 );
has 'window' => ( is => 'rw', isa => 'PfInterval', coerce => 1 );

=head2 run

run the auth log cleanup task

=cut

sub run {
    my ($self) = @_;
    my $window = $self->window;
    pf::auth_log::cleanup($window, $self->batch, $self->timeout) if $self->window;
}

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
