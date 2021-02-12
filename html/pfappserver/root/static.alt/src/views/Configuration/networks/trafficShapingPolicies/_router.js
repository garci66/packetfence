import store from '@/store'
const TheTabs = () => import(/* webpackChunkName: "Configuration" */ '../../_components/NetworksTabs')
const TheView = () => import(/* webpackChunkName: "Configuration" */ './_components/TheView')

export default [
  {
    path: 'traffic_shapings',
    name: 'traffic_shapings',
    component: TheTabs,
    props: (route) => ({ tab: 'traffic_shapings', query: route.query.query })
  },
  {
    path: 'traffic_shaping/new/:role',
    name: 'newTrafficShaping',
    component: TheView,
    props: (route) => ({ isNew: true, role: route.params.role })
  },
  {
    path: 'traffic_shaping/:id',
    name: 'traffic_shaping',
    component: TheView,
    props: (route) => ({ id: route.params.id }),
    beforeEnter: (to, from, next) => {
      store.dispatch('$_traffic_shaping_policies/getTrafficShapingPolicy', to.params.id).then(() => {
        next()
      })
    }
  }
]
