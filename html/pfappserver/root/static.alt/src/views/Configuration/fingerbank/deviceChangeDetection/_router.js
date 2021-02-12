import store from '@/store'
import BasesStoreModule from '../../bases/_store'

import { TheTabs } from '../_components/'

export const beforeEnter = (to, from, next = () => {}) => {
  if (!store.state.$_bases) {
    store.registerModule('$_bases', BasesStoreModule)
  }
  next()
}

export default [
  {
    path: 'fingerbank/device_change_detection',
    name: 'fingerbankDeviceChangeDetection',
    component: TheTabs,
    props: (route) => ({ tab: 'device_change_detection', query: route.query.query }),
    beforeEnter
  }
]
