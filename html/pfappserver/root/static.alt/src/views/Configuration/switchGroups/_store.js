/**
* "$_switch_groups" store module
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
    cache: {}, // items details
    message: '',
    itemStatus: ''
  }
}

const getters = {
  isWaiting: state => [types.LOADING, types.DELETING].includes(state.itemStatus),
  isLoading: state => state.itemStatus === types.LOADING
}

const actions = {
  all: () => {
    const params = {
      sort: 'id',
      fields: ['id', 'description'].join(','),
      limit: 1000
    }
    return api.switchGroups(params).then(response => {
      return response.items
    })
  },
  options: ({ commit }, id) => {
    commit('ITEM_REQUEST')
    if (id) {
      return api.switchGroupOptions(id).then(response => {
        commit('ITEM_SUCCESS')
        return response
      }).catch((err) => {
        commit('ITEM_ERROR', err.response)
        throw err
      })
    } else {
      return api.switchGroupsOptions().then(response => {
        commit('ITEM_SUCCESS')
        return response
      }).catch((err) => {
        commit('ITEM_ERROR', err.response)
        throw err
      })
    }
  },
  getSwitchGroup: ({ state, commit }, id) => {
    if (state.cache[id]) {
      return Promise.resolve(state.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('ITEM_REQUEST')
    return api.switchGroup(id).then(item => {
      commit('ITEM_REPLACED', item)
      api.switchGroupMembers(id).then(members => { // Fetch members
        commit('ITEM_UPDATED', { id, prop: 'members', data: members })
      })
      return JSON.parse(JSON.stringify(state.cache[id]))
    }).catch((err) => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  getSwitchGroupMembers: ({ state, commit }, id) => {
    commit('ITEM_REQUEST')
    return api.switchGroupMembers(id).then(members => {
      commit('ITEM_UPDATED', { id, prop: 'members', data: members })
      return state.cache[id].members
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  createSwitchGroup: ({ commit }, data) => {
    commit('ITEM_REQUEST')
    return api.createSwitchGroup(data).then(response => {
      commit('ITEM_REPLACED', data)
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  updateSwitchGroup: ({ commit }, data) => {
    commit('ITEM_REQUEST')
    return api.updateSwitchGroup(data).then(response => {
      commit('ITEM_REPLACED', data)
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  deleteSwitchGroup: ({ commit }, data) => {
    commit('ITEM_REQUEST', types.DELETING)
    return api.deleteSwitchGroup(data).then(response => {
      commit('ITEM_DESTROYED', data)
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  }
}

const mutations = {
  ITEM_REQUEST: (state, type) => {
    state.itemStatus = type || types.LOADING
    state.message = ''
  },
  ITEM_REPLACED: (state, data) => {
    state.itemStatus = types.SUCCESS
    Vue.set(state.cache, data.id, JSON.parse(JSON.stringify(data)))
  },
  ITEM_UPDATED: (state, params) => {
    state.itemStatus = types.SUCCESS
    if (params.id in state.cache) {
      Vue.set(state.cache[params.id], params.prop, params.data)
    }
  },
  ITEM_DESTROYED: (state, id) => {
    state.itemStatus = types.SUCCESS
    Vue.set(state.cache, id, null)
  },
  ITEM_ERROR: (state, response) => {
    state.itemStatus = types.ERROR
    if (response && response.data) {
      state.message = response.data.message
    }
  },
  ITEM_SUCCESS: (state) => {
    state.itemStatus = types.SUCCESS
  }
}

export default {
  namespaced: true,
  state,
  getters,
  actions,
  mutations
}
