import store from '@/store'
import StoreModule from './_store'

export const TheTabs = () => import(/* webpackChunkName: "Configuration" */ '../_components/ScansTabs')
const TheView = () => import(/* webpackChunkName: "Configuration" */ './_components/TheView')

export const beforeEnter = (to, from, next = () => {}) => {
  if (!store.state.$_scans)
    store.registerModule('$_scans', StoreModule)
  next()
}

export default [
  {
    path: 'scans',
    redirect: 'scans/scan_engines'
  },
  {
    path: 'scans/scan_engines',
    name: 'scanEngines',
    component: TheTabs,
    props: (route) => ({ tab: 'scan_engines', query: route.query.query }),
    beforeEnter
  },
  {
    path: 'scans/scan_engines/new/:scanType',
    name: 'newScanEngine',
    component: TheView,
    props: (route) => ({ isNew: true, scanType: route.params.scanType }),
    beforeEnter
  },
  {
    path: 'scans/scan_engine/:id',
    name: 'scanEngine',
    component: TheView,
    props: (route) => ({ id: route.params.id }),
    beforeEnter: (to, from, next) => {
      beforeEnter()
      store.dispatch('$_scans/getScanEngine', to.params.id).then(() => {
        next()
      })
    }
  },
  {
    path: 'scans/scan_engine/:id/clone',
    name: 'cloneScanEngine',
    component: TheView,
    props: (route) => ({ id: route.params.id, isClone: true }),
    beforeEnter: (to, from, next) => {
      beforeEnter()
      store.dispatch('$_scans/getScanEngine', to.params.id).then(() => {
        next()
      })
    }
  }
]
