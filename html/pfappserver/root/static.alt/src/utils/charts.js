import axios from 'axios'
import router from '@/router'
import store from '@/store'

const chartsCall = axios.create({
  baseURL: `https://${window.location.hostname}:${window.location.port}/netdata/`
})

chartsCall.interceptors.response.use((response) => {
  store.commit('session/CHARTS_OK')
  return response
}, (error) => {
  if (error.response) {
    if (error.response.status === 401 || // unauthorized
        (error.response.status === 404 && /token_info/.test(error.config.url))) {
      router.push('/expire')
    }
  }
  if (error.request) {
    store.commit('session/CHARTS_ERROR')
  }
  return Promise.reject(error)
})

export default chartsCall
