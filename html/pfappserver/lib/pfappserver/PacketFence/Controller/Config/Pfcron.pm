package pfappserver::PacketFence::Controller::Config::Pfcron;

=head1 NAME

pfappserver::PacketFence::Controller::Config::Pfcron - Catalyst Controller

=head1 DESCRIPTION

Controller for admin roles management.

=cut

use HTTP::Status qw(:constants is_error is_success);
use Moose;  # automatically turns on strict and warnings
use namespace::autoclean;

BEGIN {
    extends 'pfappserver::Base::Controller';
    with 'pfappserver::Base::Controller::Crud::Config';
    with 'pfappserver::Base::Controller::Crud::Config::Clone';
}

__PACKAGE__->config(
    action => {
        # Reconfigure the object action from pfappserver::Base::Controller::Crud
        object => { Chained => '/', PathPart => 'config/pfcron', CaptureArgs => 1 },
        # Configure access rights
        view   => { AdminRole => 'PFCRON_READ' },
        list   => { AdminRole => 'PFCRON_READ' },
        update => { AdminRole => 'PFCRON_UPDATE' },
        # The following are noops it will fail
        create => { AdminRole => 'PFCRON_READ' },
        clone  => { AdminRole => 'PFCRON_READ' },
        remove => { AdminRole => 'PFCRON_READ' },
    },
    action_args => {
        # Setting the global model and form for all actions
        '*' => { model => "Config::Pfcron", form => "Config::Pfcron" },
    },
);

=head1 METHODS

=head2 index

Usage: /config/pfcron

=cut

sub index :Path :Args(0) {
    my ($self, $c) = @_;

    $c->forward('list');
}

before [qw(create clone remove)] => sub {
    my ($self, $c) = @_;
    my $name = $c->action->name;
    $c->log->error("cannot perform the following action on a pfcron task $name");
    $c->detach();
};

before [qw(view update)] => sub {
    my ($self, $c, @args) = @_;
    my $model = $self->getModel($c);
    my $itemKey = $model->itemKey;
    my $item = $c->stash->{$itemKey};
    my $type = $item->{type};
    my $form = $c->action->{form};
    $c->stash->{current_form} = "${form}::${type}";
};

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

__PACKAGE__->meta->make_immutable unless $ENV{"PF_SKIP_MAKE_IMMUTABLE"};

1;
