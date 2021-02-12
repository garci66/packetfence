import { computed, toRefs } from '@vue/composition-api'
import i18n from '@/utils/locale'

const useItemTitle = (props) => {
  const {
    id
  } = toRefs(props)
  return computed(() => id.value.toUpperCase())
}

const useStore = (props, context, form) => {
  const {
    id
  } = toRefs(props)
  const { root: { $store } = {} } = context

  const getItem = () => $store.dispatch('$_certificates/getCertificate', id.value).then(_certificate => {
    const { status, ...certificate } = _certificate // strip out `status` from response
    return $store.dispatch('$_certificates/getCertificateInfo', id.value).then(_info => {
      const { status, ...info } = { ..._info, common_name: '', check_chain: 'enabled' } // strip out `status` from response
      return { certificate, info }
    })
  })

  return {
    isLoading: computed(() => $store.getters['$_certificates/isLoading']),
    getItem,
    updateItem: () => {
      const {
        id
      } = toRefs(props)
      const { certificate, certificate: { lets_encrypt } = {} } = form.value
      let creationPromise
      if (lets_encrypt)
        creationPromise = $store.dispatch('$_certificates/createLetsEncryptCertificate', certificate)
      else
        creationPromise = $store.dispatch('$_certificates/createCertificate', certificate)
      return creationPromise.then(() => {
        $store.dispatch('notification/info', { message: i18n.t('{certificate} certificate saved', { certificate: id.value.toUpperCase() }) })
        getItem().then(item => form.value = item)
      }).finally(() =>
        window.scrollTo(0, 0)
      )
    }
  }
}

export default {
  useItemTitle,
  useStore,
}
