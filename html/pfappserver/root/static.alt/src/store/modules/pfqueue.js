/**
* "pfqueue" store module
*/
import Vue from 'vue'
import apiCall from '@/utils/api'

const api = {
  getStats: () => {
    return apiCall.getQuiet(`queues/stats`).then(response => {
      return response.data.items
    })
  },
  pollTaskStatus: (id) => {
    return apiCall.getQuiet(`pfqueue/task/${id}/status/poll`).then(response => {
      return response.data
    })
  }
}

const types = {
  LOADING: 'loading',
  SUCCESS: 'success',
  ERROR: 'error'
}

// Default values
const initialState = () => {
  return {
    stats: false,
    tasks: false,
    message: '',
    requestStatus: ''
  }
}

const getters = {
  isLoading: state => state.requestStatus === types.LOADING,
  stats: state => state.stats || []
}

const actions = {
  getStats: ({ commit, state }) => {
    commit('PFQUEUE_REQUEST')
    return new Promise((resolve, reject) => {
      api.getStats().then(data => {
        commit('PFQUEUE_SUCCESS', data)
        resolve(state.stats)
      }).catch(err => {
        commit('PFQUEUE_ERROR', err.response)
        reject(err)
      })
    })
  },
  pollTaskStatus: ({ dispatch }, id) => {
    return api.pollTaskStatus(id).then(data => { // 'poll' returns immediately, or timeout after 15s
      if ('status' in data && data.status === 202) { // 202: in progress
        return dispatch('pollTaskStatus', id) // recurse
      }
      if ('error' in data) {
        throw new Error(data.error.message)
      }
      return data.item
    }).catch(err => {
      throw err
    })
  }
}

const mutations = {
  PFQUEUE_REQUEST: (state) => {
    state.requestStatus = types.LOADING
    state.message = ''
  },
  PFQUEUE_SUCCESS: (state, data) => {
    Vue.set(state, 'stats', data)
    state.requestStatus = types.SUCCESS
    state.message = ''
  },
  PFQUEUE_ERROR: (state, data) => {
    state.requestStatus = types.ERROR
    const { response: { data: { message } = {} } = {} } = data
    if (message) {
      state.message = message
    }
  },
  // eslint-disable-next-line no-unused-vars
  $RESET: (state) => {
    state = initialState()
  }
}

export default {
  namespaced: true,
  state: initialState(),
  getters,
  actions,
  mutations
}
