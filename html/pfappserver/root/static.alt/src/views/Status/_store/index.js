/**
* "$_status" store module
*/
import Vue from 'vue'
import api from '../_api'
import { blacklistedServices } from '@/store/modules/services'

const STORAGE_CHARTS_KEY = 'dashboard-charts'

const types = {
  LOADING: 'loading',
  ENABLING: 'enabling',
  DISABLING: 'disabling',
  RESTARTING: 'restarting',
  STARTING: 'starting',
  STOPPING: 'stopping',
  DELETING: 'deleting',
  SUCCESS: 'success',
  ERROR: 'error'
}

const state = () => {
  return {
    allCharts: {},
    allChartsStatus: '',
    charts: localStorage.getItem(STORAGE_CHARTS_KEY) ? JSON.parse(localStorage.getItem(STORAGE_CHARTS_KEY)) : [],
    alarmsStatus: '',
    alarms: {},
    services: [],
    servicesStatus: '',
    clusterPromise: null,
    cluster: null,
    clusterStatus: '',
    clusterServices: [],
    clusterServicesStatus: ''
  }
}

const getters = {
  isLoading: state => state.allChartsStatus === types.LOADING,
  allModules: state => {
    let modules = []
    let unasignedCharts = false
    for (const chart of state.allCharts) {
      if (chart.module && !modules.includes(chart.module)) {
        modules.push(chart.module)
      } else if (!chart.module) {
        unasignedCharts = true
      }
    }
    if (unasignedCharts) {
      modules.push('other')
    }
    return modules
  },
  isServicesWaiting: state => [types.LOADING, types.DELETING].includes(state.servicesStatus),
  isServicesLoading: state => [types.LOADING, types.STOPPING, types.STARTING, types.RESTARTING].includes(state.servicesStatus) || state.services.filter(service => ![200, 'error'].includes(service.status)).length > 0,
  isServicesStopping: state => state.servicesStatus === types.STOPPING,
  isServicesStarting: state => state.servicesStatus === types.STARTING,
  isServicesRestarting: state => state.servicesStatus === types.RESTARTING,
  blacklistedServices: () => blacklistedServices,
  isClusterServicesLoading: state => state.clusterServicesStatus === types.LOADING,
  clusterIPs: state => state.cluster.map(server => server.management_ip ),
  uniqueCharts: state => {
    let charts = [].concat(...Object.values(state.allCharts))
    // Remove duplicates
    for (let i = 0; i < charts.length; ++i) {
      for (let j = i + 1; j < charts.length; ++j) {
          if (charts[i].id === charts[j].id)
          charts.splice(j--, 1);
      }
    }
    return charts
  },
  hostsForChart: state => id => {
    return Object.keys(state.allCharts).filter(ip => {
      return state.allCharts[ip].find(chart => chart.id === id)
    })
  }
}

const actions = {
  allCharts: ({ state, getters, commit }) => {
    if (state.allCharts.length > 0) {
      return Promise.resolve(state.allCharts)
    }
    if (state.allChartsStatus !== types.LOADING) {
      commit('ALL_CHARTS_REQUEST')
      // Assume getCluster has been dispatched
      return Promise.all(getters.clusterIPs.map(ip => {
        return api.charts(ip).then(charts => {
          commit('ALL_CHARTS_UPDATED', { [ip]: charts })
        }).catch(err => {
          commit('ALL_CHARTS_ERROR')
          commit('session/CHARTS_ERROR', err.response, { root: true })
          throw err
        })
      }))
    }
  },
  getChart: ({ commit }, id) => {
    return api.chart(id).catch(err => {
      commit('ALL_CHARTS_ERROR')
      commit('session/CHARTS_ERROR', err.response, { root: true })
    })
  },
  addChart: ({ state, commit }, definition) => {
    let chart = {
      id: definition.id,
      name: definition.name,
      title: definition.title,
      library: definition.library,
      cols: definition.cols
    }
    commit('CHARTS_UPDATED', chart)
    localStorage.setItem(STORAGE_CHARTS_KEY, JSON.stringify(state.charts))
  },
  alarms: ({ state, commit }, ip) => {
    if (state.alarmsStatus !== types.LOADING) {
      commit('ALARMS_REQUEST')
      return api.alarms(ip).then(data => {
        commit('ALARMS_UPDATED', data)
        return data
      }).catch(err => {
        commit('ALARMS_ERROR')
        commit('session/CHARTS_ERROR', err.response, { root: true })
      })
    }
    throw new Error('$_status/alarms: another task is already in progress')
  },
  getServices: ({ state, commit }) => {
    if (state.services.length > 0) {
      return Promise.resolve(state.services)
    }
    if (state.servicesStatus !== types.LOADING) {
      commit('SERVICES_REQUEST')
      return api.services().then(services => {
        commit('SERVICES_UPDATED', services)
        for (let [index, service] of state.services.entries()) {
          commit('SERVICE_REQUEST', index)
          api.service(service.name, 'status').then(status => {
            commit('SERVICE_UPDATED', { index, status })
          })
        }
      }).catch(err => {
        commit('SERVICES_ERROR')
        commit('session/API_ERROR', err.response, { root: true })
        throw err
      })
    }
    throw new Error('$_status/getServices: another task is already in progress')
  },
  disableService: ({ state, commit }, id) => {
    const index = state.services.findIndex(service => service.name === id)
    commit('SERVICE_DISABLING', index)
    return api.disableService(id).then(() => {
      commit('SERVICE_DISABLED', index)
      commit('SERVICE_REQUEST', index)
      api.service(state.services[index].name, 'status').then(status => {
        commit('SERVICE_UPDATED', { index, status })
        return state.services[index]
      })
    }).catch((err) => {
      commit('SERVICE_ERROR', index)
      throw err
    })
  },
  enableService: ({ state, commit }, id) => {
    const index = state.services.findIndex(service => service.name === id)
    commit('SERVICE_ENABLING', index)
    return api.enableService(id).then(() => {
      commit('SERVICE_ENABLED', index)
      commit('SERVICE_REQUEST', index)
      api.service(state.services[index].name, 'status').then(status => {
        commit('SERVICE_UPDATED', { index, status })
        return state.services[index]
      })
    }).catch((err) => {
      commit('SERVICE_ERROR', index)
      throw err
    })
  },
  restartService: ({ state, commit }, id) => {
    if (id in blacklistedServices) return
    const index = state.services.findIndex(service => service.name === id)
    commit('SERVICE_RESTARTING', index)
    return api.restartService(id).then(() => {
      commit('SERVICE_RESTARTED', index)
      commit('SERVICE_REQUEST', index)
      api.service(state.services[index].name, 'status').then(status => {
        commit('SERVICE_UPDATED', { index, status })
        return state.services[index]
      })
    }).catch((err) => {
      commit('SERVICE_ERROR', index)
      throw err
    })
  },
  restartAllServices: ({ state, commit }) => {
    commit('SERVICES_RESTARTING')
    const promises = []
    state.services.filter(service => !(blacklistedServices.includes(service.name))).forEach((service, index) => {
      commit('SERVICE_RESTARTING', index)
      promises.push(
        api.restartService(service.name).then(response => {
          commit('SERVICE_RESTARTED', index)
          return { [index]: ['SERVICE_RESTARTED', response] }
        }).catch((err) => {
          commit('SERVICE_ERROR', index)
          return { [index]: ['SERVICE_ERROR', err] }
        })
      )
    })
    return Promise.all(promises.map(p => p.catch(e => e))).then(response => {
      commit('SERVICES_SUCCESS')
      response.forEach(item => {
        const index = Object.keys(item)[0]
        const { [index]: [ mutation ] } = item
        switch (mutation) {
          case 'SERVICE_RESTARTED':
            commit('SERVICE_REQUEST', index)
            api.service(state.services[index].name, 'status').then(status => {
              commit('SERVICE_UPDATED', { index, status })
            })
            break
          case 'SERVICE_ERROR':
            commit('SERVICE_REQUEST', index)
            api.service(state.services[index].name, 'status').then(status => {
              commit('SERVICE_UPDATED', { index, status })
            })
            break
        }
      })
      return response
    })
  },
  startService: ({ state, commit }, id) => {
    if (id in blacklistedServices) return
    const index = state.services.findIndex(service => service.name === id)
    commit('SERVICE_STARTING', index)
    return api.startService(id).then(() => {
      commit('SERVICE_STARTED', index)
      commit('SERVICE_REQUEST', index)
      api.service(state.services[index].name, 'status').then(status => {
        commit('SERVICE_UPDATED', { index, status })
        return state.services[index]
      })
    }).catch((err) => {
      commit('SERVICE_ERROR', index)
      throw err
    })
  },
  startAllServices: ({ state, commit }) => {
    commit('SERVICES_STARTING')
    const promises = []
    state.services.filter(service => !(blacklistedServices.includes(service.name))).forEach((service, index) => {
      if (!service.alive) {
        commit('SERVICE_STARTING', index)
        promises.push(
          api.startService(service.name).then(response => {
            commit('SERVICE_STARTED', index)
            return { [index]: ['SERVICE_STARTED', response] }
          }).catch((err) => {
            commit('SERVICE_ERROR', index)
            return { [index]: ['SERVICE_ERROR', err] }
          })
        )
      }
    })
    return Promise.all(promises.map(p => p.catch(e => e))).then(response => {
      commit('SERVICES_SUCCESS')
      response.forEach(item => {
        const index = Object.keys(item)[0]
        const { [index]: [ mutation ] } = item
        switch (mutation) {
          case 'SERVICE_STARTED':
            commit('SERVICE_REQUEST', index)
            api.service(state.services[index].name, 'status').then(status => {
              commit('SERVICE_UPDATED', { index, status })
            })
            break
          case 'SERVICE_ERROR':
            commit('SERVICE_REQUEST', index)
            api.service(state.services[index].name, 'status').then(status => {
              commit('SERVICE_UPDATED', { index, status })
            })
            break
        }
      })
      return response
    })
  },
  stopService: ({ state, commit }, id) => {
    if (id in blacklistedServices) return
    const index = state.services.findIndex(service => service.name === id)
    commit('SERVICE_STOPPING', index)
    return api.stopService(id).then(() => {
      commit('SERVICE_STOPPED', index)
      commit('SERVICE_REQUEST', index)
      api.service(state.services[index].name, 'status').then(status => {
        commit('SERVICE_UPDATED', { index, status })
        return state.services[index]
      })
    }).catch((err) => {
      commit('SERVICE_ERROR', index)
      throw err
    })
  },
  stopAllServices: ({ state, commit }) => {
    commit('SERVICES_STOPING')
    const promises = []
    state.services.filter(service => !(blacklistedServices.includes(service.name))).forEach((service, index) => {
      if (service.alive) {
        commit('SERVICE_STOPING', index)
        promises.push(
          api.stopService(service.name).then(response => {
            commit('SERVICE_STOPED', index)
            return { [index]: ['SERVICE_STOPED', response] }
          }).catch((err) => {
            commit('SERVICE_ERROR', index)
            return { [index]: ['SERVICE_ERROR', err] }
          })
        )
      }
    })
    return Promise.all(promises.map(p => p.catch(e => e))).then(response => {
      commit('SERVICES_SUCCESS')
      response.forEach(item => {
        const index = Object.keys(item)[0]
        const { [index]: [ mutation ] } = item
        switch (mutation) {
          case 'SERVICE_STOPED':
            commit('SERVICE_REQUEST', index)
            api.service(state.services[index].name, 'status').then(status => {
              commit('SERVICE_UPDATED', { index, status })
            })
            break
          case 'SERVICE_ERROR':
            commit('SERVICE_REQUEST', index)
            api.service(state.services[index].name, 'status').then(status => {
              commit('SERVICE_UPDATED', { index, status })
            })
            break
        }
      })
      return response
    })
  },
  getCluster: ({ state, dispatch, commit }) => {
    if (!state.clusterPromise) {
      const clusterPromise = api.cluster().then(servers => {
        if (servers.length) {
          commit('CLUSTER_UPDATED', servers)
        } else {
          return dispatch('system/getSummary', null, { root: true }).then(summary => {
            const server = [{ host: summary.hostname, management_ip: '127.0.0.1' }]
            commit('CLUSTER_UPDATED', server)
          })
        }
      }).catch(err => {
        commit('CLUSTER_ERROR')
        throw err
      })
      commit('CLUSTER_REQUEST', clusterPromise)
    }
    return state.clusterPromise
  },
  getClusterServices: ({ state, commit }) => {
    if (state.clusterServicesStatus !== types.LOADING) {
      commit('CLUSTER_SERVICES_REQUEST')
      Promise.all(state.cluster.map(server => {
        commit('CLUSTER_SERVICES_UPDATED', { host: server.host, services: [] }) // placeholder to maintain natural order
        return api.clusterServices(server.host).then(server => {
          commit('CLUSTER_SERVICES_UPDATED', server)
        }).catch(() => {
          // Ignore error -- don't let Promise.all immediately rejects with an error
          commit('CLUSTER_SERVICES_UPDATED', { host: 'crap', services: [] })
        })
      })).then(() => {
        commit('CLUSTER_SERVICES_UPDATED')
      })
    }
  }
}

const mutations = {
  ALL_CHARTS_REQUEST: (state) => {
    state.allChartsStatus = types.LOADING
  },
  ALL_CHARTS_UPDATED: (state, charts) => {
    const [ first ] = Object.keys(charts)
    state.allChartsStatus = types.SUCCESS
    Vue.set(state.allCharts, first, charts[first])
  },
  ALL_CHARTS_ERROR: (state) => {
    state.allChartsStatus = types.ERROR
    state.allCharts = {}
  },
  CHARTS_UPDATED: (state, chart) => {
    if (state.charts.filter(c => c.id === chart.id).length) {
      // eslint-disable-next-line
      console.warn('chart ' + chart.id + ' already on dashboard')
    } else {
      state.charts.push(chart)
    }
  },
  ALARMS_REQUEST: (state) => {
    state.alarmsStatus = types.LOADING
  },
  ALARMS_UPDATED: (state) => {
    state.alarmsStatus = types.SUCCESS
    // state.alarms = alarms // no caching necessary for now
  },
  ALARMS_ERROR: (state) => {
    state.alarmsStatus = types.ERROR
    state.alarms = {}
  },
  SERVICES_REQUEST: (state) => {
    state.servicesStatus = types.LOADING
  },
  SERVICES_UPDATED: (state, services) => {
    state.servicesStatus = types.SUCCESS
    Vue.set(state, 'services', services.map(name => {
      return { name }
    }))
  },
  SERVICES_SUCCESS: (state) => {
    state.servicesStatus = types.SUCCESS
  },
  SERVICES_ERROR: (state) => {
    state.servicesStatus = types.ERROR
  },
  SERVICES_STOPPING: (state) => {
    state.servicesStatus = types.STOPPING
  },
  SERVICES_STARTING: (state) => {
    state.servicesStatus = types.STARTING
  },
  SERVICES_RESTARTING: (state) => {
    state.servicesStatus = types.RESTARTING
  },
  SERVICE_DISABLING: (state, index) => {
    Vue.set(state.services[index], 'status', types.DISABLING)
    state.servicesStatus = types.LOADING
  },
  SERVICE_DISABLED: (state, index) => {
    Vue.set(state.services[index], 'status', types.SUCCESS)
    state.servicesStatus = types.SUCCESS
  },
  SERVICE_ENABLING: (state, index) => {
    Vue.set(state.services[index], 'status', types.ENABLING)
    state.servicesStatus = types.LOADING
  },
  SERVICE_ENABLED: (state, index) => {
    Vue.set(state.services[index], 'status', types.SUCCESS)
    state.servicesStatus = types.SUCCESS
  },
  SERVICE_RESTARTING: (state, index) => {
    Vue.set(state.services[index], 'status', types.RESTARTING)
    state.servicesStatus = types.LOADING
  },
  SERVICE_RESTARTED: (state, index) => {
    Vue.set(state.services[index], 'status', types.SUCCESS)
    state.servicesStatus = types.SUCCESS
  },
  SERVICE_STARTING: (state, index) => {
    Vue.set(state.services[index], 'status', types.STARTING)
    state.servicesStatus = types.LOADING
  },
  SERVICE_STARTED: (state, index) => {
    Vue.set(state.services[index], 'status', types.SUCCESS)
    state.servicesStatus = types.SUCCESS
  },
  SERVICE_STOPPING: (state, index) => {
    Vue.set(state.services[index], 'status', types.STOPPING)
    state.servicesStatus = types.LOADING
  },
  SERVICE_STOPPED: (state, index) => {
    Vue.set(state.services[index], 'status', types.SUCCESS)
    state.servicesStatus = types.SUCCESS
  },
  SERVICE_ERROR: (state, index) => {
    Vue.set(state.services[index], 'status', types.ERROR)
    state.servicesStatus = types.ERROR
  },
  SERVICE_REQUEST: (state, index) => {
    Vue.set(state.services, index, Object.assign(state.services[index], { loading: true }))
  },
  SERVICE_UPDATED: (state, data) => {
    data.status.enabled = data.status.enabled === 1
    data.status.alive = data.status.alive === 1
    data.status.loading = false
    Vue.set(state.services, data.index, Object.assign(state.services[data.index], data.status))
  },
  CLUSTER_REQUEST: (state, clusterPromise) => {
    state.clusterStatus = types.LOADING
    state.clusterPromise = clusterPromise
  },
  CLUSTER_UPDATED: (state, servers) => {
    state.clusterStatus = types.SUCCESS
    state.cluster = servers
  },
  CLUSTER_ERROR: (state) => {
    state.clusterServicesStatus = types.ERROR
    state.clusterPromise = null
  },
  CLUSTER_SERVICES_REQUEST: (state) => {
    state.clusterServicesStatus = types.LOADING
  },
  CLUSTER_SERVICES_UPDATED: (state, server) => {
    if (server) {
      let found = state.clusterServices.find(s => s.host === server.host)
      if (found) { // replace
        state.clusterServices = state.clusterServices.map(s => {
          const { host } = s
          return (host === server.host)
            ? server
            : s
        })
      }
      else { // append
        state.clusterServices.push(server)
      }
    } else {
      // No more data -- done fetching services
      state.clusterServicesStatus = types.SUCCESS
    }
  },
  CLUSTER_SERVICES_ERROR: (state) => {
    state.clusterStatus = types.ERROR
  }
}

export default {
  namespaced: true,
  state,
  getters,
  actions,
  mutations
}
