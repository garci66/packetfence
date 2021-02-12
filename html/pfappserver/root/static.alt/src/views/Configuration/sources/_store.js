/**
* "$_sources" store module
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
    saml_metadata: {}, // SAML
    message: '',
    itemStatus: ''
  }
}

const getters = {
  isWaiting: state => [types.LOADING, types.DELETING].includes(state.itemStatus),
  isLoading: state => state.itemStatus === types.LOADING
}

const actions = {
  all: ({ commit }) => {
    const params = {
      sort: null, // use natural ordering
      fields: ['id', 'description', 'type', 'class'].join(','),
      limit: 1000
    }
    commit('ITEM_REQUEST')
    return api.authenticationSources(params).then(response => {
      commit('ITEM_SUCCESS')
      return response.items
    }).catch((err) => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  optionsById: ({ commit }, id) => {
    commit('ITEM_REQUEST')
    return api.authenticationSourceOptions(id).then(response => {
      commit('ITEM_SUCCESS')
      return response
    }).catch((err) => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  optionsBySourceType: ({ commit }, sourceType) => {
    commit('ITEM_REQUEST')
    return api.authenticationSourcesOptions(sourceType).then(response => {
      commit('ITEM_SUCCESS')
      return response
    }).catch((err) => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  getAuthenticationSourcesByType: (context, type) => {
    const params = {
      sort: 'id',
      fields: ['id', 'description', 'class'].join(','),
      type: type,
      limit: 1000
    }
    return api.authenticationSources(params).then(response => {
      return response.items
    })
  },
  getAuthenticationSource: ({ state, commit }, id) => {
    if (state.cache[id]) {
      return Promise.resolve(state.cache[id]).then(cache => JSON.parse(JSON.stringify(cache)))
    }
    commit('ITEM_REQUEST')
    return api.authenticationSource(id).then(item => {
      commit('ITEM_REPLACED', item)
      return JSON.parse(JSON.stringify(item))
    }).catch((err) => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  getAuthenticationSourceSAMLMetaData: ({ state, commit }, id) => {
    if (state.saml_metadata[id]) {
      return Promise.resolve(state.saml_metadata[id]).then(saml_metadata => saml_metadata)
    }
    commit('ITEM_REQUEST')
    return api.authenticationSourceSAMLMetaData(id).then(xml => {
      commit('SAML_METADATA_REPLACED', { id, xml })
      return xml
    }).catch((err) => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  createAuthenticationSource: ({ commit }, data) => {
    // fix #4597
    //  set administration_rules.actions.value = '1' where administration_rules.actions.type = 'mark_as_sponsor'
    const { administration_rules: administrationRules = [] } = data
    if (administrationRules && 'length' in administrationRules) {
      administrationRules.forEach((administrationRule, rIndex) => {
        const { actions = [] } = administrationRule
        actions.forEach((action, aIndex) => {
          if (action.type === 'mark_as_sponsor') {
            data.administration_rules[rIndex].actions[aIndex].value = 1
          }
        })
      })
    }
    commit('ITEM_REQUEST')
    return api.createAuthenticationSource(data).then(response => {
      commit('ITEM_REPLACED', data)
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  updateAuthenticationSource: ({ commit }, data) => {
    // fix #4597
    //  set administration_rules.actions.value = '1' where administration_rules.actions.type = 'mark_as_sponsor'
    const { administration_rules: administrationRules = [] } = data
    if (administrationRules && 'length' in administrationRules) {
      administrationRules.forEach((administrationRule, rIndex) => {
        const { actions = [] } = administrationRule
        actions.forEach((action, aIndex) => {
          if (action.type === 'mark_as_sponsor') {
            data.administration_rules[rIndex].actions[aIndex].value = 1
          }
        })
      })
    }
    commit('ITEM_REQUEST')
    return api.updateAuthenticationSource(data).then(response => {
      commit('ITEM_REPLACED', data)
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  deleteAuthenticationSource: ({ commit }, data) => {
    commit('ITEM_REQUEST', types.DELETING)
    return api.deleteAuthenticationSource(data).then(response => {
      commit('ITEM_DESTROYED', data)
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  sortAuthenticationSources: ({ commit }, data) => {
    const params = {
      items: data
    }
    commit('ITEM_REQUEST', types.LOADING)
    return api.sortAuthenticationSources(params).then(response => {
      commit('ITEM_SUCCESS')
      return response
    }).catch(err => {
      commit('ITEM_ERROR', err.response)
      throw err
    })
  },
  testAuthenticationSource: ({ commit }, data) => {
    commit('ITEM_REQUEST')
    return api.testAuthenticationSource(data).then(response => {
      commit('ITEM_SUCCESS')
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
  SAML_METADATA_REPLACED: (state, { id, xml }) => {
    state.itemStatus = types.SUCCESS
    Vue.set(state.saml_metadata, id, xml)
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
