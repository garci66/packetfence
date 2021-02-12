import acl from '@/utils/acl'
import ConfigurationView from '../'

/* Policies Access Control */
const PoliciesAccessControlSection = () => import(/* webpackChunkName: "Configuration" */ '../_components/PoliciesAccessControlSection')
import RolesRoutes from '../roles/_router'
import DomainsRoutes from '../domains/_router'
import RealmsRoutes from '../realms/_router'
import SourcesRoutes from '../sources/_router'
import SwitchesRoutes from '../switches/_router'
import SwitchGroupsRoutes from '../switchGroups/_router'
import ConnectionProfilesRoutes from '../connectionProfiles/_router'
import RemoteConnectionProfilesRoutes from '../remoteConnectionProfiles/_router'

/* Compliance */
const ComplianceSection = () => import(/* webpackChunkName: "Configuration" */ '../_components/ComplianceSection')
import FingerbankRoutes from '../fingerbank/_router'
import NetworkBehaviorPoliciesRoutes from '../networkBehaviorPolicy/_router'
import ScanEnginesRoutes from '../scanEngines/_router'
import SecurityEventsRoutes from '../securityEvents/_router'
import WmiRulesRoutes from '../wmiRules/_router'

/* Integration */
const IntegrationSection = () => import(/* webpackChunkName: "Configuration" */ '../_components/IntegrationSection')
import FirewallsRoutes from '../firewalls/_router'
import CiscoMobilityServicesEngineRoutes from '../ciscoMobilityServicesEngine/_router'
import WebServicesRoutes from '../webServices/_router'
import SwitchTemplatesRoutes from '../switchTemplates/_router'
import SyslogParsersRoutes from '../syslogParsers/_router'
import SyslogForwardersRoutes from '../syslogForwarders/_router'
import WrixRoutes from '../wrix/_router'
import PkiRoutes from '../pki/_router'

/* Advanced Access Configuration */
const AdvancedAccessConfigurationSection = () => import(/* webpackChunkName: "Configuration" */ '../_components/AdvancedAccessConfigurationSection')
import CaptivePortalRoutes from '../captivePortal/_router'
import FilterEnginesRoutes from '../filterEngines/_router'
import BillingTiersRoutes from '../billingTiers/_router'
import PkiProvidersRoutes from '../pkiProviders/_router'
import PortalModulesRoutes from '../portalModules/_router'
import AccessDurationsRoutes from '../accessDurations/_router'
import ProvisionersRoutes from '../provisioners/_router'
import SelfServicesRoutes from '../selfServices/_router'

/* Network Configuration */
const NetworkConfigurationSection = () => import(/* webpackChunkName: "Configuration" */ '../_components/NetworkConfigurationSection')
import NetworksRoutes from '../networks/_router'
import SnmpTrapsRoutes from '../snmpTraps/_router'
import FloatingDevicesRoutes from '../floatingDevices/_router'
import SslCertificatesRoutes from '../sslCertificates/_router'

/* System Configuration */
const SystemConfigurationSection = () => import(/* webpackChunkName: "Configuration" */ '../_components/SystemConfigurationSection')
import GeneralRoutes from '../general/_router'
import AlertingRoutes from '../alerting/_router'
import AdvancedRoutes from '../advanced/_router'
import MaintenanceTasksRoutes from '../maintenanceTasks/_router'
import ServicesRoutes from '../services/_router'
import DatabaseRoutes from '../database/_router'
import ActiveActiveRoutes from '../activeActive/_router'
import RadiusRoutes from '../radius/_router'
import DnsRoutes from '../dns/_router'
import AdminRolesRoutes from '../adminRoles/_router'

const route = {
  path: '/configuration',
  name: 'configuration',
  redirect: '/configuration/policies_access_control',
  component: ConfigurationView,
  meta: {
    can: () => acl.$can('read', 'configuration_main'), // has ACL for 1+ children
    transitionDelay: 300 * 2 // See _transitions.scss => $slide-bottom-duration
  },
  children: [
    /**
     * Policies Access Control
     */
    {
      path: 'policies_access_control',
      component: PoliciesAccessControlSection
    },
    ...RolesRoutes,
    ...DomainsRoutes,
    ...RealmsRoutes,
    ...SourcesRoutes,
    ...SwitchesRoutes,
    ...SwitchGroupsRoutes,
    ...ConnectionProfilesRoutes,
    ...RemoteConnectionProfilesRoutes,

    /**
     * Compliance
     */

    {
      path: 'compliance',
      component: ComplianceSection
    },
    ...FingerbankRoutes,
    ...NetworkBehaviorPoliciesRoutes,
    ...ScanEnginesRoutes,
    ...SecurityEventsRoutes,
    ...WmiRulesRoutes,

    /**
     * Integration
     */
    {
      path: 'integration',
      component: IntegrationSection
    },
    ...FirewallsRoutes,
    ...CiscoMobilityServicesEngineRoutes,
    ...WebServicesRoutes,
    ...SwitchTemplatesRoutes,
    ...SyslogParsersRoutes,
    ...SyslogForwardersRoutes,
    ...WrixRoutes,
    ...PkiRoutes,

    /**
     *  Advanced Access Configuration
     */
    {
      path: 'advanced_access_configuration',
      component: AdvancedAccessConfigurationSection
    },
    ...FilterEnginesRoutes,
    ...CaptivePortalRoutes,
    ...BillingTiersRoutes,
    ...PkiProvidersRoutes,
    ...ProvisionersRoutes,
    ...PortalModulesRoutes,
    ...AccessDurationsRoutes,
    ...SelfServicesRoutes,

    /**
     * Network Configuration
     */
    {
      path: 'network_configuration',
      component: NetworkConfigurationSection
    },
    ...NetworksRoutes,
    ...FloatingDevicesRoutes,
    ...SnmpTrapsRoutes,

    /**
     * System Configuration
     */
    {
      path: 'system_configuration',
      component: SystemConfigurationSection
    },
    ...GeneralRoutes,
    ...AlertingRoutes,
    ...AdvancedRoutes,
    ...MaintenanceTasksRoutes,
    ...ServicesRoutes,
    ...DatabaseRoutes,
    ...ActiveActiveRoutes,
    ...RadiusRoutes,
    ...DnsRoutes,
    ...AdminRolesRoutes,
    ...SslCertificatesRoutes
  ]
}

export default route
