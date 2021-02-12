import store from '@/store'
import StoreModule from './_store'

const TheList = () => import(/* webpackChunkName: "Configuration" */ '../_components/SyslogForwardersList')
const TheView = () => import(/* webpackChunkName: "Configuration" */ './_components/TheView')

export const beforeEnter = (to, from, next = () => {}) => {
  if (!store.state.$_syslog_forwarders)
    store.registerModule('$_syslog_forwarders', StoreModule)
  next()
}

export default [
  {
    path: 'syslog',
    name: 'syslogForwarders',
    component: TheList,
    props: (route) => ({ query: route.query.query }),
    beforeEnter
  },
  {
    path: 'syslog/new/:syslogForwarderType',
    name: 'newSyslogForwarder',
    component: TheView,
    props: (route) => ({ isNew: true, syslogForwarderType: route.params.syslogForwarderType }),
    beforeEnter
  },
  {
    path: 'syslog/:id',
    name: 'syslogForwarder',
    component: TheView,
    props: (route) => ({      id: route.params.id }),
    beforeEnter: (to, from, next) => {
      beforeEnter()
      store.dispatch('$_syslog_forwarders/getSyslogForwarder', to.params.id).then(() => {
        next()
      })
    }
  },
  {
    path: 'syslog/:id/clone',
    name: 'cloneSyslogForwarder',
    component: TheView,
    props: (route) => ({ id: route.params.id, isClone: true }),
    beforeEnter: (to, from, next) => {
      beforeEnter()
      store.dispatch('$_syslog_forwarders/getSyslogForwarder', to.params.id).then(() => {
        next()
      })
    }
  }
]
