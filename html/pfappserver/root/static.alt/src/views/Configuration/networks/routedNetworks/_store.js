/**
* "$_routed_networks" store module
*/
import Vue from 'vue'
import api from './_api'
import { columns as columnsRoutedNetwork } from '../../_config/routedNetwork'

const types = {
  LOADING: 'loading',
  DELETING: 'deleting',
  SUCCESS: 'success',
  ERROR: 'error'
}

// Default values
const state = () => {
  return {
    cache: {},
    message: '',
    status: ''
  }
}

const getters = {
  isWaiting: state => [types.LOADING, types.DELETING].includes(state.status),
  isLoading: state => state.status === types.LOADING
}

const actions = {
  all: ({ commit }) => {
    const params = {
      sort: 'id',
      fields: columnsRoutedNetwork.map(r => r.key).join(','),
      limit: 1000
    }
    commit('ROUTED_NETWORK_REQUEST')
    return api.routedNetworks(params).then(response => {
      commit('ROUTED_NETWORK_SUCCESS')
      return response.items
    }).catch((err) => {
      commit('ROUTED_NETWORK_ERROR', err.response)
      throw err
    })
  },
  options: ({ commit }, id) => {
    commit('ROUTED_NETWORK_REQUEST')
    if (id) {
      return api.routedNetworkOptions(id).then(response => {
        commit('ROUTED_NETWORK_SUCCESS')
        return response
      }).catch((err) => {
        commit('ROUTED_NETWORK_ERROR', err.response)
        throw err
      })
    } else {
      return api.routedNetworksOptions().then(response => {
        commit('ROUTED_NETWORK_SUCCESS')
        return response
      }).catch((err) => {
        commit('ROUTED_NETWORK_ERROR', err.response)
        throw err
      })
    }
  },
  getRoutedNetwork: ({ state, commit }, id) => {
    if (state.cache[id]) {
      return Promise.resolve(state.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('ROUTED_NETWORK_REQUEST')
    return api.routedNetwork(id).then(item => {
      commit('ROUTED_NETWORK_REPLACED', { ...item, id })
      return JSON.parse(JSON.stringify(item))
    }).catch((err) => {
      commit('ROUTED_NETWORK_ERROR', err.response)
      throw err
    })
  },
  createRoutedNetwork: ({ commit }, data) => {
    commit('ROUTED_NETWORK_REQUEST')
    return api.createRoutedNetwork(data).then(response => {
      commit('ROUTED_NETWORK_REPLACED', data)
      return response
    }).catch(err => {
      commit('ROUTED_NETWORK_ERROR', err.response)
      throw err
    })
  },
  updateRoutedNetwork: ({ commit }, data) => {
    commit('ROUTED_NETWORK_REQUEST')
    return api.updateRoutedNetwork(data).then(response => {
      commit('ROUTED_NETWORK_REPLACED', data)
      return response
    }).catch(err => {
      commit('ROUTED_NETWORK_ERROR', err.response)
      throw err
    })
  },
  deleteRoutedNetwork: ({ commit }, id) => {
    commit('ROUTED_NETWORK_REQUEST')
    return api.deleteRoutedNetwork(id).then(response => {
      commit('ROUTED_NETWORK_DESTROYED', id)
      return response
    }).catch((err) => {
      commit('ROUTED_NETWORK_ERROR', err.response)
      throw err
    })
  }

}

const mutations = {
  ROUTED_NETWORK_REQUEST: (state, type) => {
    state.status = type || types.LOADING
    state.message = ''
  },
  ROUTED_NETWORK_REPLACED: (state, data) => {
    state.status = types.SUCCESS
    Vue.set(state.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  ROUTED_NETWORK_DESTROYED: (state, id) => {
    state.status = types.SUCCESS
    Vue.set(state.cache, id, null)
  },
  ROUTED_NETWORK_ERROR: (state, response) => {
    state.status = types.ERROR
    if (response && response.data) {
      state.message = response.data.message
    }
  },
  ROUTED_NETWORK_SUCCESS: (state) => {
    state.status = types.SUCCESS
  }
}

export default {
  namespaced: true,
  state,
  getters,
  actions,
  mutations
}
