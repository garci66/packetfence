import api from '../_api'

const state = {
  status: ''
}

const getters = {
  isLoading: state => state.status === 'loading'
}

const actions = {
  login: ({state, getters, commit, dispatch}, user) => {
    return new Promise((resolve, reject) => {
      commit('LOGIN_REQUEST')
      api.login(user).then(response => {
        let token = response.data.token
        commit('LOGIN_SUCCESS', token)
        dispatch('session/update', token, { root: true }).then(() => {
          resolve(response)
        })
      }).catch(err => {
        commit('LOGIN_ERROR', err.response)
        dispatch('session/delete', null, { root: true })
        reject(err)
      })
    })
  },
  logout: ({commit, dispatch}) => {
    return new Promise((resolve, reject) => {
      dispatch('session/delete', null, { root: true })
      resolve()
    })
  }
}

const mutations = {
  LOGIN_REQUEST: (state) => {
    state.status = 'loading'
  },
  LOGIN_SUCCESS: (state, token) => {
    state.status = 'success'
  },
  LOGIN_ERROR: (state, response) => {
    state.status = 'error'
    if (response && response.data) {
      state.message = response.data.message
    }
  }
}

export default {
  namespaced: true,
  state,
  getters,
  actions,
  mutations
}
