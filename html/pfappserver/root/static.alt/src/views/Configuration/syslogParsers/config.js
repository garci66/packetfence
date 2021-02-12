import { pfFieldType } from '@/globals/pfField'
import i18n from '@/utils/locale'

export const regexRuleActions = {
  add_person: {
    value: 'add_person',
    text: i18n.t('Create new user account'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'pid, $pid' }
    }
  },
  close_security_event: {
    value: 'close_security_event',
    text: i18n.t('Close security event'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, vid, VID' }
    }
  },
  deregister_node_ip: {
    value: 'deregister_node_ip',
    text: i18n.t('Deregister node by IP'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'ip, $ip' }
    }
  },
  dynamic_register_node: {
    value: 'dynamic_register_node',
    text: i18n.t('Register node by MAC'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, username, $username' }
    }
  },
  modify_node: {
    value: 'modify_node',
    text: i18n.t('Modify node by MAC'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac' }
    }
  },
  modify_person: {
    value: 'modify_person',
    text: i18n.t('Modify existing user'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'pid, $pid' }
    }
  },
  reevaluate_access: {
    value: 'reevaluate_access',
    text: i18n.t('Reevaluate access by MAC'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, reason, $reason' }
    }
  },
  register_node: {
    value: 'register_node',
    text: i18n.t('Register a new node by PID'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, pid, $pid' }
    }
  },
  register_node_ip: {
    value: 'register_node_ip',
    text: i18n.t('Register node by IP'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'ip, $ip, pid, $pid' }
    }
  },
  release_all_security_events: {
    value: 'release_all_security_events',
    text: i18n.t('Release all security events for node by MAC'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: '$mac' }
    }
  },
  role_detail: {
    value: 'role_detail',
    text: i18n.t('Get role details'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'role, $role' }
    }
  },
  trigger_scan: {
    value: 'trigger_scan',
    text: i18n.t('Launch a scan for the device'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: '$ip, mac, $mac, net_type, TYPE' }
    }
  },
  trigger_security_event: {
    value: 'trigger_security_event',
    text: i18n.t('Trigger a security event'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, tid, TYPEID, type, TYPE' }
    }
  },
  unreg_node_for_pid: {
    value: 'unreg_node_for_pid',
    text: i18n.t('Deregister node by PID'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'pid, $pid' }
    }
  },
  update_ip4log: {
    value: 'update_ip4log',
    text: i18n.t('Update ip4log by IP and MAC'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, ip, $ip' }
    }
  },
  update_ip6log: {
    value: 'update_ip6log',
    text: i18n.t('Update ip6log by IP and MAC'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'mac, $mac, ip, $ip' }
    }
  },
  update_role_configuration: {
    value: 'update_role_configuration',
    text: i18n.t('Update role configuration'),
    types: [pfFieldType.SUBSTRING],
    siblings: {
      api_parameters: { default: 'role, $role' }
    }
  }
}
