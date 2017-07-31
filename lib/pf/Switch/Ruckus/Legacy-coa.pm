package pf::Switch::Ruckus::Legacy;

=head1 NAME

pf::Switch::Ruckus::Legacy

=head1 SYNOPSIS

Override base methods to comply with legacy hardware

=cut

use strict;
use warnings;

use base ('pf::Switch::Ruckus');
use pf::roles::custom;
use pf::accounting qw(node_accounting_dynauth_attr);
use pf::util::radius qw(perform_coa perform_disconnect);
use pf::accounting qw(node_accounting_current_sessionid);
use pf::constants;
use pf::util;

sub description { 'Ruckus Wireless Controllers - Legacy' }

=over

=item deauthenticateMacDefault

Overrides base method to send Acct-Session-Id withing the RADIUS disconnect request

=cut

sub deauthenticateMacDefault {
    my ( $self, $mac, $is_dot1x ) = @_;
    my $logger = $self->logger;

    if ( !$self->isProductionMode() ) {
        $logger->info("not in production mode... we won't perform deauthentication");
        return 1;
    }

    #Fetching the acct-session-id
    my $dynauth = node_accounting_dynauth_attr($mac);

    $logger->debug("deauthenticate $mac using RADIUS Disconnect-Request deauth method");
    return $self->radiusDisconnect(
        $mac, { 'Acct-Session-Id' => $dynauth->{'acctsessionid'}, 'User-Name' => $dynauth->{'username'} },
    );
}

=item radiusDisconnect
Sends a RADIUS Disconnect-Request to the NAS with the MAC as the Calling-Station-Id to disconnect.
Optionally you can provide other attributes as an hashref.
Uses L<pf::util::radius> for the low-level RADIUS stuff.
=cut

# TODO consider whether we should handle retries or not?

sub radiusDisconnect {
    my ($self, $mac, $add_attributes_ref) = @_;
    my $logger = $self->logger;

    # initialize
    $add_attributes_ref = {} if (!defined($add_attributes_ref));

    if (!defined($self->{'_radiusSecret'})) {
        $logger->warn(
            "Unable to perform RADIUS CoA-Request on $self->{'_ip'}: RADIUS Shared Secret not configured"
        );
        return;
    }

    $logger->info("deauthenticating $mac");

    # Where should we send the RADIUS CoA-Request?
    # to network device by default
    my $send_disconnect_to = $self->{'_ip'};
    # but if controllerIp is set, we send there
    if (defined($self->{'_controllerIp'}) && $self->{'_controllerIp'} ne '') {
        $logger->info("controllerIp is set, we will use controller $self->{_controllerIp} to perform deauth");
        $send_disconnect_to = $self->{'_controllerIp'};
    }
    # allowing client code to override where we connect with NAS-IP-Address
    if ( defined($add_attributes_ref->{'NAS-IP-Address'}) && $add_attributes_ref->{'NAS-IP-Address'} ne '' ) {
        $logger->info("'NAS-IP-Address' additionnal attribute is set. Using it '" . $add_attributes_ref->{'NAS-IP-Address'} . "' to perform deauth");
        $send_disconnect_to = $add_attributes_ref->{'NAS-IP-Address'};
    }

    my $response;
    try {
        my $connection_info = {
            nas_ip => $send_disconnect_to,
            secret => $self->{'_radiusSecret'},
            LocalAddr => $self->deauth_source_ip($send_disconnect_to),
        };
        
        if (defined($self->{'_disconnectPort'}) && $self->{'_disconnectPort'} ne '') {
            $connection_info->{'nas_port'} = $self->{'_disconnectPort'};
        }

        $logger->debug("network device supports roles. Evaluating role to be returned");
        my $roleResolver = pf::roles::custom->instance();
        my $role = $roleResolver->getRoleForNode($mac, $self);	

        my $acctsessionid = node_accounting_current_sessionid($mac);
        # transforming MAC to the expected format 00-11-22-33-CA-FE
        $mac = uc($mac);
        $mac =~ s/:/-/g;

        # Standard Attributes
        my $attributes_ref = {
            'Calling-Station-Id' => $mac,
            'NAS-IP-Address' => $send_disconnect_to,
            'Acct-Session-Id' => $acctsessionid,
        };

        # merging additional attributes provided by caller to the standard attributes
        $attributes_ref = { %$attributes_ref, %$add_attributes_ref };

        if ( $self->shouldUseCoA({role => $role}) ) {

            $attributes_ref = {
                %$attributes_ref,
                'Ruckus-User-Groups' => $role,
            };
            $logger->info("[$self->{'_ip'}] Returning ACCEPT with role: $role");
            $response = perform_coa($connection_info, $attributes_ref);

        }
        else {
            $response = perform_disconnect($connection_info, $attributes_ref);
        }
    } catch {
        chomp;
        $logger->warn("Unable to perform RADIUS CoA-Request: $_");
        $logger->error("Wrong RADIUS secret or unreachable network device...") if ($_ =~ /^Timeout/);
    };
    return if (!defined($response));

    return $TRUE if ( ($response->{'Code'} eq 'Disconnect-ACK') || ($response->{'Code'} eq 'CoA-ACK') );

    $logger->warn(
        "Unable to perform RADIUS Disconnect-Request."
        . ( defined($response->{'Code'}) ? " $response->{'Code'}" : 'no RADIUS code' ) . ' received'
        . ( defined($response->{'Error-Cause'}) ? " with Error-Cause: $response->{'Error-Cause'}." : '' )
    );
    return;
}



=back

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

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
