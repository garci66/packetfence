import store from '@/store'
import StoreModule from './_store'

const TheList = () => import(/* webpackChunkName: "Configuration" */ '../_components/WrixLocationsList')
const TheView = () => import(/* webpackChunkName: "Configuration" */ './_components/TheView')

export const beforeEnter = (to, from, next = () => {}) => {
  if (!store.state.$_wrix_locations)
    store.registerModule('$_wrix_locations', StoreModule)
  next()
}

export default [
  {
    path: 'wrix',
    name: 'wrixLocations',
    component: TheList,
    props: (route) => ({ query: route.query.query }),
    beforeEnter
  },
  {
    path: 'wrix/new',
    name: 'newWrixLocation',
    component: TheView,
    props: () => ({ isNew: true }),
    beforeEnter
  },
  {
    path: 'wrix/:id',
    name: 'wrixLocation',
    component: TheView,
    props: (route) => ({ id: route.params.id }),
    beforeEnter: (to, from, next) => {
      beforeEnter()
      store.dispatch('$_wrix_locations/getWrixLocation', to.params.id).then(() => {
        next()
      })
    }
  },
  {
    path: 'wrix/:id/clone',
    name: 'cloneWrixLocation',
    component: TheView,
    props: (route) => ({ id: route.params.id, isClone: true }),
    beforeEnter: (to, from, next) => {
      beforeEnter()
      store.dispatch('$_wrix_locations/getWrixLocation', to.params.id).then(() => {
        next()
      })
    }
  }
]
