package pf::UnifiedApi::Controller::Config::Subtype;

=head1 NAME

pf::UnifiedApi::Controller::Config::Subtype -

=cut

=head1 DESCRIPTION

pf::UnifiedApi::Controller::Config::Subtype

=cut

use strict;
use warnings;
use Mojo::Base qw(pf::UnifiedApi::Controller::Config);

sub form_class_by_type {
    my ($self, $type) = @_;
    my $lookup = $self->type_lookup;
    return exists $lookup->{$type} ? $lookup->{$type} : undef;
}

sub form {
    my ($self, $item) = @_;
    my $type = $item->{type};
    if ( !defined $type ) {
        $self->render_error(422, "Unable to validate", [{ type => "type field is required"}]);
        return undef;
    }
    my $class = $self->form_class_by_type($type);

    if ( !$class  ){
        $self->render_error(422, "Unable to validate", [{ type => "type field is invalid '$type'"}]);
        return undef;
    }

    return $class->new;
}

sub type_lookup {
    return {}
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
