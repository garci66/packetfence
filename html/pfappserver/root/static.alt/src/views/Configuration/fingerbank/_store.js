/**
* "$_fingerbank" store module
*/
import Vue from 'vue'
import api from './_api'

const types = {
  LOADING: 'loading',
  DELETING: 'deleting',
  SUCCESS: 'success',
  ERROR: 'error'
}

// Default values
const state = () => {
  return {
    accountInfo: {
      cache: false,
      message: '',
      status: ''
    },
    canUseNbaEndpoints: {
      cache: false,
      message: '',
      status: ''
    },
    generalSettings: {
      cache: false,
      message: '',
      status: ''
    },
    deviceChangeDetection: {
      cache: false,
      message: '',
      status: ''
    },
    combinations: {
      cache: {},
      message: '',
      status: ''
    },
    devices: {
      cache: {},
      message: '',
      status: ''
    },
    dhcpFingerprints: {
      cache: {},
      message: '',
      status: ''
    },
    dhcpVendors: {
      cache: {},
      message: '',
      status: ''
    },
    dhcpv6Fingerprints: {
      cache: {},
      message: '',
      status: ''
    },
    dhcpv6Enterprises: {
      cache: {},
      message: '',
      status: ''
    },
    macVendors: {
      cache: {},
      message: '',
      status: ''
    },
    userAgents: {
      cache: {},
      message: '',
      status: ''
    },
    updateDatabase: {
      message: '',
      status: ''
    }
  }
}

const getters = {
  isAccountInfoWaiting: state => [types.LOADING, types.DELETING].includes(state.accountInfo.status),
  isAccountInfoLoading: state => state.accountInfo.status === types.LOADING,

  isCanUseNbaEndpointsWaiting: state => [types.LOADING, types.DELETING].includes(state.canUseNbaEndpoints.status),
  isCanUseNbaEndpointsLoading: state => state.canUseNbaEndpoints.status === types.LOADING,

  isGeneralSettingsWaiting: state => [types.LOADING, types.DELETING].includes(state.generalSettings.status),
  isGeneralSettingsLoading: state => state.generalSettings.status === types.LOADING,

  isDeviceChangeDetectionWaiting: state => [types.LOADING, types.DELETING].includes(state.deviceChangeDetection.status),
  isDeviceChangeDetectionLoading: state => state.deviceChangeDetection.status === types.LOADING,

  isCombinationsWaiting: state => [types.LOADING, types.DELETING].includes(state.combinations.status),
  isCombinationsLoading: state => state.combinations.status === types.LOADING,

  isDevicesWaiting: state => [types.LOADING, types.DELETING].includes(state.devices.status),
  isDevicesLoading: state => state.devices.status === types.LOADING,

  isDhcpFingerprintsWaiting: state => [types.LOADING, types.DELETING].includes(state.dhcpFingerprints.status),
  isDhcpFingerprintsLoading: state => state.dhcpFingerprints.status === types.LOADING,

  isDhcpVendorsWaiting: state => [types.LOADING, types.DELETING].includes(state.dhcpVendors.status),
  isDhcpVendorsLoading: state => state.dhcpVendors.status === types.LOADING,

  isDhcpv6FingerprintsWaiting: state => [types.LOADING, types.DELETING].includes(state.dhcpv6Fingerprints.status),
  isDhcpv6FingerprintsLoading: state => state.dhcpv6Fingerprints.status === types.LOADING,

  isDhcpv6EnterprisesWaiting: state => [types.LOADING, types.DELETING].includes(state.dhcpv6Enterprises.status),
  isDhcpv6EnterprisesLoading: state => state.dhcpv6Enterprises.status === types.LOADING,

  isMacVendorsWaiting: state => [types.LOADING, types.DELETING].includes(state.macVendors.status),
  isMacVendorsLoading: state => state.macVendors.status === types.LOADING,

  isUserAgentsWaiting: state => [types.LOADING, types.DELETING].includes(state.userAgents.status),
  isUserAgentsLoading: state => state.userAgents.status === types.LOADING,

  isUpdateDatabaseLoading: state => state.updateDatabase.status === types.LOADING
}

const actions = {
  getAccountInfo: ({ state, commit }) => {
    if (state.accountInfo.cache) {
      return Promise.resolve(state.accountInfo.cache).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('ACCOUNT_INFO_REQUEST')
    return api.fingerbankAccountInfo().then(info => {
      commit('ACCOUNT_INFO_REPLACED', info)
      return info
    }).catch(err => {
      commit('ACCOUNT_INFO_ERROR', err.response)
      throw err
    })
  },
  getCanUseNbaEndpoints: ({ state, commit }) => {
    if (state.canUseNbaEndpoints.cache) {
      return Promise.resolve(state.canUseNbaEndpoints.cache).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('CAN_USE_NBA_ENDPOINTS_REQUEST')
    return api.fingerbankCanUseNbaEndpoints().then(info => {
      commit('CAN_USE_NBA_ENDPOINTS_REPLACED', info)
      return info
    }).catch(err => {
      commit('CAN_USE_NBA_ENDPOINTS_ERROR', err.response)
      throw err
    })
  },
  getGeneralSettings: ({ state, commit }) => {
    if (state.generalSettings.cache) {
      return Promise.resolve(state.generalSettings.cache).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('GENERAL_SETTINGS_REQUEST')
    const params = {
      sort: 'id'
    }
    return api.fingerbankGeneralSettings(params).then(response => {
      // response is split multipart, refactor required
      let refactored = {}
      response.forEach((section) => {
        refactored[section.id] = Object.keys(section)
          .filter(key => !(['id'].includes(key)))
          .reduce((obj, key) => {
            obj[key] = section[key]
            return obj
          }, {})
      })
      commit('GENERAL_SETTINGS_REPLACED', refactored)
      return refactored
    }).catch(err => {
      commit('GENERAL_SETTINGS_ERROR', err.response)
      throw err
    })
  },
  // TODO - Test (Issue #4139)
  optionsGeneralSettings: ({ commit }) => {
    commit('GENERAL_SETTINGS_REQUEST')
    return api.fingerbankGeneralSettingsOptions().then(response => {
      commit('GENERAL_SETTINGS_SUCCESS')
      return response
    }).catch(err => {
      commit('GENERAL_SETTINGS_ERROR', err.response)
      throw err
    })
  },
  setGeneralSettings: ({ commit }, data) => {
    commit('GENERAL_SETTINGS_REQUEST')
    let promises = []
    Object.keys(data).forEach(id => {
      let refactored = { ...data[id], ...{ id } }
      promises.push(api.fingerbankUpdateGeneralSetting(id, refactored))
    })
    return Promise.all(promises).then(response => {
      commit('GENERAL_SETTINGS_REPLACED', data)
      return response
    }).catch(err => {
      commit('GENERAL_SETTINGS_ERROR', err.response)
      throw err
    })
  },
  combinations: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankCombinations(params).then(response => {
      return response.items
    })
  },
  getCombination: ({ state, commit }, id) => {
    if (state.combinations.cache[id]) {
      return Promise.resolve(state.combinations.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('COMBINATION_REQUEST')
    return api.fingerbankCombination(id).then(item => {
      commit('COMBINATION_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('COMBINATION_ERROR', err.response)
      throw err
    })
  },
  createCombination: ({ commit }, data) => {
    commit('COMBINATION_REQUEST')
    return api.fingerbankCreateCombination(data).then(response => {
      data.id = response.id
      commit('COMBINATION_REPLACED', data)
      return response
    }).catch(err => {
      commit('COMBINATION_ERROR', err.response)
      throw err
    })
  },
  updateCombination: ({ commit }, data) => {
    commit('COMBINATION_REQUEST')
    return api.fingerbankUpdateCombination(data).then(response => {
      commit('COMBINATION_REPLACED', data)
      return response
    }).catch(err => {
      commit('COMBINATION_ERROR', err.response)
      throw err
    })
  },
  deleteCombination: ({ commit }, data) => {
    commit('COMBINATION_REQUEST', types.DELETING)
    return api.fingerbankDeleteCombination(data).then(response => {
      commit('COMBINATION_DESTROYED', data)
      return response
    }).catch(err => {
      commit('COMBINATION_ERROR', err.response)
      throw err
    })
  },
  devices: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankDevices(params).then(response => {
      return response.items
    })
  },
  getDevice: ({ state, commit }, id) => {
    if (state.devices.cache[id]) {
      return Promise.resolve(state.devices.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('DEVICE_REQUEST')
    return api.fingerbankDevice(id).then(item => {
      commit('DEVICE_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('DEVICE_ERROR', err.response)
      throw err
    })
  },
  createDevice: ({ commit }, data) => {
    commit('DEVICE_REQUEST')
    return api.fingerbankCreateDevice(data).then(response => {
      data.id = response.id
      commit('DEVICE_REPLACED', data)
      return response
    }).catch(err => {
      commit('DEVICE_ERROR', err.response)
      throw err
    })
  },
  updateDevice: ({ commit }, data) => {
    commit('DEVICE_REQUEST')
    return api.fingerbankUpdateDevice(data).then(response => {
      commit('DEVICE_REPLACED', data)
      return response
    }).catch(err => {
      commit('DEVICE_ERROR', err.response)
      throw err
    })
  },
  deleteDevice: ({ commit }, data) => {
    commit('DEVICE_REQUEST', types.DELETING)
    return api.fingerbankDeleteDevice(data).then(response => {
      commit('DEVICE_DESTROYED', data)
      return response
    }).catch(err => {
      commit('DEVICE_ERROR', err.response)
      throw err
    })
  },
  dhcpFingerprints: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankDhcpFingerprints(params).then(response => {
      return response.items
    })
  },
  getDhcpFingerprint: ({ state, commit }, id) => {
    if (state.dhcpFingerprints.cache[id]) {
      return Promise.resolve(state.dhcpFingerprints.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('DHCP_FINGERPRINT_REQUEST')
    return api.fingerbankDhcpFingerprint(id).then(item => {
      commit('DHCP_FINGERPRINT_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('DHCP_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  createDhcpFingerprint: ({ commit }, data) => {
    commit('DHCP_FINGERPRINT_REQUEST')
    return api.fingerbankCreateDhcpFingerprint(data).then(response => {
      data.id = response.id
      commit('DHCP_FINGERPRINT_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCP_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  updateDhcpFingerprint: ({ commit }, data) => {
    commit('DHCP_FINGERPRINT_REQUEST')
    return api.fingerbankUpdateDhcpFingerprint(data).then(response => {
      commit('DHCP_FINGERPRINT_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCP_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  deleteDhcpFingerprint: ({ commit }, data) => {
    commit('DHCP_FINGERPRINT_REQUEST', types.DELETING)
    return api.fingerbankDeleteDhcpFingerprint(data).then(response => {
      commit('DHCP_FINGERPRINT_DESTROYED', data)
      return response
    }).catch(err => {
      commit('DHCP_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  dhcpVendors: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankDhcpVendors(params).then(response => {
      return response.items
    })
  },
  getDhcpVendor: ({ state, commit }, id) => {
    if (state.dhcpVendors.cache[id]) {
      return Promise.resolve(state.dhcpVendors.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('DHCP_VENDOR_REQUEST')
    return api.fingerbankDhcpVendor(id).then(item => {
      commit('DHCP_VENDOR_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('DHCP_VENDOR_ERROR', err.response)
      throw err
    })
  },
  createDhcpVendor: ({ commit }, data) => {
    commit('DHCP_VENDOR_REQUEST')
    return api.fingerbankCreateDhcpVendor(data).then(response => {
      data.id = response.id
      commit('DHCP_VENDOR_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCP_VENDOR_ERROR', err.response)
      throw err
    })
  },
  updateDhcpVendor: ({ commit }, data) => {
    commit('DHCP_VENDOR_REQUEST')
    return api.fingerbankUpdateDhcpVendor(data).then(response => {
      commit('DHCP_VENDOR_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCP_VENDOR_ERROR', err.response)
      throw err
    })
  },
  deleteDhcpVendor: ({ commit }, data) => {
    commit('DHCP_VENDOR_REQUEST', types.DELETING)
    return api.fingerbankDeleteDhcpVendor(data).then(response => {
      commit('DHCP_VENDOR_DESTROYED', data)
      return response
    }).catch(err => {
      commit('DHCP_VENDOR_ERROR', err.response)
      throw err
    })
  },
  dhcpv6Fingerprints: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankDhcpv6Fingerprints(params).then(response => {
      return response.items
    })
  },
  getDhcpv6Fingerprint: ({ state, commit }, id) => {
    if (state.dhcpv6Fingerprints.cache[id]) {
      return Promise.resolve(state.dhcpv6Fingerprints.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('DHCPV6_FINGERPRINT_REQUEST')
    return api.fingerbankDhcpv6Fingerprint(id).then(item => {
      commit('DHCPV6_FINGERPRINT_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('DHCPV6_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  createDhcpv6Fingerprint: ({ commit }, data) => {
    commit('DHCPV6_FINGERPRINT_REQUEST')
    return api.fingerbankCreateDhcpv6Fingerprint(data).then(response => {
      data.id = response.id
      commit('DHCPV6_FINGERPRINT_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCPV6_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  updateDhcpv6Fingerprint: ({ commit }, data) => {
    commit('DHCPV6_FINGERPRINT_REQUEST')
    return api.fingerbankUpdateDhcpv6Fingerprint(data).then(response => {
      commit('DHCPV6_FINGERPRINT_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCPV6_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  deleteDhcpv6Fingerprint: ({ commit }, data) => {
    commit('DHCPV6_FINGERPRINT_REQUEST', types.DELETING)
    return api.fingerbankDeleteDhcpv6Fingerprint(data).then(response => {
      commit('DHCPV6_FINGERPRINT_DESTROYED', data)
      return response
    }).catch(err => {
      commit('DHCPV6_FINGERPRINT_ERROR', err.response)
      throw err
    })
  },
  dhcpv6Enterprises: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankDhcpv6Enterprises(params).then(response => {
      return response.items
    })
  },
  getDhcpv6Enterprise: ({ state, commit }, id) => {
    if (state.dhcpv6Enterprises.cache[id]) {
      return Promise.resolve(state.dhcpv6Enterprises.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('DHCPV6_ENTERPRISE_REQUEST')
    return api.fingerbankDhcpv6Enterprise(id).then(item => {
      commit('DHCPV6_ENTERPRISE_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('DHCPV6_ENTERPRISE_ERROR', err.response)
      throw err
    })
  },
  createDhcpv6Enterprise: ({ commit }, data) => {
    commit('DHCPV6_ENTERPRISE_REQUEST')
    return api.fingerbankCreateDhcpv6Enterprise(data).then(response => {
      data.id = response.id
      commit('DHCPV6_ENTERPRISE_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCPV6_ENTERPRISE_ERROR', err.response)
      throw err
    })
  },
  updateDhcpv6Enterprise: ({ commit }, data) => {
    commit('DHCPV6_ENTERPRISE_REQUEST')
    return api.fingerbankUpdateDhcpv6Enterprise(data).then(response => {
      commit('DHCPV6_ENTERPRISE_REPLACED', data)
      return response
    }).catch(err => {
      commit('DHCPV6_ENTERPRISE_ERROR', err.response)
      throw err
    })
  },
  deleteDhcpv6Enterprise: ({ commit }, data) => {
    commit('DHCPV6_ENTERPRISE_REQUEST', types.DELETING)
    return api.fingerbankDeleteDhcpv6Enterprise(data).then(response => {
      commit('DHCPV6_ENTERPRISE_DESTROYED', data)
      return response
    }).catch(err => {
      commit('DHCPV6_ENTERPRISE_ERROR', err.response)
      throw err
    })
  },
  macVendors: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankMacVendors(params).then(response => {
      return response.items
    })
  },
  getMacVendor: ({ state, commit }, id) => {
    if (state.macVendors.cache[id]) {
      return Promise.resolve(state.macVendors.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('MAC_VENDOR_REQUEST')
    return api.fingerbankMacVendor(id).then(item => {
      commit('MAC_VENDOR_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('MAC_VENDOR_ERROR', err.response)
      throw err
    })
  },
  createMacVendor: ({ commit }, data) => {
    commit('MAC_VENDOR_REQUEST')
    return api.fingerbankCreateMacVendor(data).then(response => {
      data.id = response.id
      commit('MAC_VENDOR_REPLACED', data)
      return response
    }).catch(err => {
      commit('MAC_VENDOR_ERROR', err.response)
      throw err
    })
  },
  updateMacVendor: ({ commit }, data) => {
    commit('MAC_VENDOR_REQUEST')
    return api.fingerbankUpdateMacVendor(data).then(response => {
      commit('MAC_VENDOR_REPLACED', data)
      return response
    }).catch(err => {
      commit('MAC_VENDOR_ERROR', err.response)
      throw err
    })
  },
  deleteMacVendor: ({ commit }, data) => {
    commit('MAC_VENDOR_REQUEST', types.DELETING)
    return api.fingerbankDeleteMacVendor(data).then(response => {
      commit('MAC_VENDOR_DESTROYED', data)
      return response
    }).catch(err => {
      commit('MAC_VENDOR_ERROR', err.response)
      throw err
    })
  },
  userAgents: () => {
    const params = {
      sort: 'id',
      fields: ['id'].join(',')
    }
    return api.fingerbankUserAgents(params).then(response => {
      return response.items
    })
  },
  getUserAgent: ({ state, commit }, id) => {
    if (state.userAgents.cache[id]) {
      return Promise.resolve(state.userAgents.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('USER_AGENT_REQUEST')
    return api.fingerbankUserAgent(id).then(item => {
      commit('USER_AGENT_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch(err => {
      commit('USER_AGENT_ERROR', err.response)
      throw err
    })
  },
  createUserAgent: ({ commit }, data) => {
    commit('USER_AGENT_REQUEST')
    return api.fingerbankCreateUserAgent(data).then(response => {
      data.id = response.id
      commit('USER_AGENT_REPLACED', data)
      return response
    }).catch(err => {
      commit('USER_AGENT_ERROR', err.response)
      throw err
    })
  },
  updateUserAgent: ({ commit }, data) => {
    commit('USER_AGENT_REQUEST')
    return api.fingerbankUpdateUserAgent(data).then(response => {
      commit('USER_AGENT_REPLACED', data)
      return response
    }).catch(err => {
      commit('USER_AGENT_ERROR', err.response)
      throw err
    })
  },
  deleteUserAgent: ({ commit }, data) => {
    commit('USER_AGENT_REQUEST', types.DELETING)
    return api.fingerbankDeleteUserAgent(data).then(response => {
      commit('USER_AGENT_DESTROYED', data)
      return response
    }).catch(err => {
      commit('USER_AGENT_ERROR', err.response)
      throw err
    })
  },
  updateDatabase: ({ commit }, data) => {
    commit('UPDATE_DATABASE_REQUEST')
    return api.fingerbankUpdateDatabase().then(response => {
      commit('UPDATE_DATABASE_SUCCESS', data)
      return response
    }).catch(err => {
      commit('UPDATE_DATABASE_ERROR', err.response)
      throw err
    })
  }
}

const mutations = {
  ACCOUNT_INFO_REQUEST: (state, type) => {
    state.accountInfo.status = type || types.LOADING
    state.accountInfo.message = ''
  },
  ACCOUNT_INFO_REPLACED: (state, data) => {
    state.accountInfo.status = types.SUCCESS
    Vue.set(state.accountInfo, 'cache', JSON.parse(JSON.stringify(data)))
  },
  ACCOUNT_INFO_ERROR: (state, response) => {
    state.accountInfo.status = types.ERROR
    if (response && response.data) {
      state.accountInfo.message = response.data.message
    }
  },
  CAN_USE_NBA_ENDPOINTS_REQUEST: (state, type) => {
    state.canUseNbaEndpoints.status = type || types.LOADING
    state.canUseNbaEndpoints.message = ''
  },
  CAN_USE_NBA_ENDPOINTS_REPLACED: (state, data) => {
    state.canUseNbaEndpoints.status = types.SUCCESS
    Vue.set(state.canUseNbaEndpoints, 'cache', JSON.parse(JSON.stringify(data)))
  },
  CAN_USE_NBA_ENDPOINTS_ERROR: (state, response) => {
    state.canUseNbaEndpoints.status = types.ERROR
    if (response && response.data) {
      state.canUseNbaEndpoints.message = response.data.message
    }
  },
  GENERAL_SETTINGS_REQUEST: (state, type) => {
    state.generalSettings.status = type || types.LOADING
    state.generalSettings.message = ''
  },
  GENERAL_SETTINGS_REPLACED: (state, data) => {
    state.generalSettings.status = types.SUCCESS
    if (!state.generalSettings.cache)
      Vue.set(state.generalSettings, 'cache', {})
    Vue.set(state.generalSettings.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  GENERAL_SETTINGS_ERROR: (state, response) => {
    state.generalSettings.status = types.ERROR
    if (response && response.data) {
      state.generalSettings.message = response.data.message
    }
  },
  GENERAL_SETTINGS_SUCCESS: (state) => {
    state.generalSettings.status = types.SUCCESS
  },
  COMBINATION_REQUEST: (state, type) => {
    state.combinations.status = type || types.LOADING
    state.combinations.message = ''
  },
  COMBINATION_REPLACED: (state, data) => {
    state.combinations.status = types.SUCCESS
    Vue.set(state.combinations.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  COMBINATION_DESTROYED: (state, id) => {
    state.combinations.status = types.SUCCESS
    Vue.set(state.combinations.cache, id, null)
  },
  COMBINATION_ERROR: (state, response) => {
    state.combinations.status = types.ERROR
    if (response && response.data) {
      state.combinations.message = response.data.message
    }
  },
  COMBINATION_SUCCESS: (state) => {
    state.combinations.status = types.SUCCESS
  },
  DEVICE_REQUEST: (state, type) => {
    state.devices.status = type || types.LOADING
    state.devices.message = ''
  },
  DEVICE_REPLACED: (state, data) => {
    state.devices.status = types.SUCCESS
    Vue.set(state.devices.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  DEVICE_DESTROYED: (state, id) => {
    state.devices.status = types.SUCCESS
    Vue.set(state.devices.cache, id, null)
  },
  DEVICE_ERROR: (state, response) => {
    state.devices.status = types.ERROR
    if (response && response.data) {
      state.devices.message = response.data.message
    }
  },
  DHCP_FINGERPRINT_REQUEST: (state, type) => {
    state.dhcpFingerprints.status = type || types.LOADING
    state.dhcpFingerprints.message = ''
  },
  DHCP_FINGERPRINT_REPLACED: (state, data) => {
    state.dhcpFingerprints.status = types.SUCCESS
    Vue.set(state.dhcpFingerprints.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  DHCP_FINGERPRINT_DESTROYED: (state, id) => {
    state.dhcpFingerprints.status = types.SUCCESS
    Vue.set(state.dhcpFingerprints.cache, id, null)
  },
  DHCP_FINGERPRINT_ERROR: (state, response) => {
    state.dhcpFingerprints.status = types.ERROR
    if (response && response.data) {
      state.dhcpFingerprints.message = response.data.message
    }
  },
  DHCP_VENDOR_REQUEST: (state, type) => {
    state.dhcpFingerprints.status = type || types.LOADING
    state.dhcpVendors.message = ''
  },
  DHCP_VENDOR_REPLACED: (state, data) => {
    state.dhcpFingerprints.status = types.SUCCESS
    Vue.set(state.dhcpVendors.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  DHCP_VENDOR_DESTROYED: (state, id) => {
    state.dhcpFingerprints.status = types.SUCCESS
    Vue.set(state.dhcpVendors.cache, id, null)
  },
  DHCP_VENDOR_ERROR: (state, response) => {
    state.dhcpFingerprints.status = types.ERROR
    if (response && response.data) {
      state.dhcpVendors.message = response.data.message
    }
  },
  DHCPV6_FINGERPRINT_REQUEST: (state, type) => {
    state.dhcpv6Fingerprints.status = type || types.LOADING
    state.dhcpv6Fingerprints.message = ''
  },
  DHCPV6_FINGERPRINT_REPLACED: (state, data) => {
    state.dhcpv6Fingerprints.status = types.SUCCESS
    Vue.set(state.dhcpv6Fingerprints.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  DHCPV6_FINGERPRINT_DESTROYED: (state, id) => {
    state.dhcpv6Fingerprints.status = types.SUCCESS
    Vue.set(state.dhcpv6Fingerprints.cache, id, null)
  },
  DHCPV6_FINGERPRINT_ERROR: (state, response) => {
    state.dhcpv6Fingerprints.status = types.ERROR
    if (response && response.data) {
      state.dhcpv6Fingerprints.message = response.data.message
    }
  },
  DHCPV6_ENTERPRISE_REQUEST: (state, type) => {
    state.dhcpv6Enterprises.status = type || types.LOADING
    state.dhcpv6Enterprises.message = ''
  },
  DHCPV6_ENTERPRISE_REPLACED: (state, data) => {
    state.dhcpv6Enterprises.status = types.SUCCESS
    Vue.set(state.dhcpv6Enterprises.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  DHCPV6_ENTERPRISE_DESTROYED: (state, id) => {
    state.dhcpv6Enterprises.status = types.SUCCESS
    Vue.set(state.dhcpv6Enterprises.cache, id, null)
  },
  DHCPV6_ENTERPRISE_ERROR: (state, response) => {
    state.dhcpv6Enterprises.status = types.ERROR
    if (response && response.data) {
      state.dhcpv6Enterprises.message = response.data.message
    }
  },
  MAC_VENDOR_REQUEST: (state, type) => {
    state.macVendors.status = type || types.LOADING
    state.macVendors.message = ''
  },
  MAC_VENDOR_REPLACED: (state, data) => {
    state.macVendors.status = types.SUCCESS
    Vue.set(state.macVendors.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  MAC_VENDOR_DESTROYED: (state, id) => {
    state.macVendors.status = types.SUCCESS
    Vue.set(state.macVendors.cache, id, null)
  },
  MAC_VENDOR_ERROR: (state, response) => {
    state.macVendors.status = types.ERROR
    if (response && response.data) {
      state.macVendors.message = response.data.message
    }
  },
  USER_AGENT_REQUEST: (state, type) => {
    state.userAgents.status = type || types.LOADING
    state.userAgents.message = ''
  },
  USER_AGENT_REPLACED: (state, data) => {
    state.userAgents.status = types.SUCCESS
    Vue.set(state.userAgents.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  USER_AGENT_DESTROYED: (state, id) => {
    state.userAgents.status = types.SUCCESS
    Vue.set(state.userAgents.cache, id, null)
  },
  USER_AGENT_ERROR: (state, response) => {
    state.userAgents.status = types.ERROR
    if (response && response.data) {
      state.userAgents.message = response.data.message
    }
  },
  UPDATE_DATABASE_REQUEST: (state, type) => {
    state.updateDatabase.status = type || types.LOADING
    state.updateDatabase.message = ''
  },
  UPDATE_DATABASE_ERROR: (state, response) => {
    state.updateDatabase.status = types.ERROR
    if (response && response.data) {
      state.updateDatabase.message = response.data.message
    }
  },
  UPDATE_DATABASE_SUCCESS: (state) => {
    state.updateDatabase.status = types.SUCCESS
  }
}

export default {
  namespaced: true,
  state,
  getters,
  actions,
  mutations
}
