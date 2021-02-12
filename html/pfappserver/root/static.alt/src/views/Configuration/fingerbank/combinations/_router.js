import store from '@/store'
import { TheTabs } from '../_components/'

const TheView = () => import(/* webpackChunkName: "Fingerbank" */ './_components/TheView')

export default [
  {
    path: 'fingerbank/combinations',
    name: 'fingerbankCombinations',
    component: TheTabs,
    props: (route) => ({ tab: 'combinations', query: route.query.query })
  },
  {
    path: 'fingerbank/local/combinations/new',
    name: 'newFingerbankCombination',
    component: TheView,
    props: () => ({ isNew: true })
  },
  {
    path: 'fingerbank/local/combination/:id',
    name: 'fingerbankCombination',
    component: TheView,
    props: (route) => ({ id: route.params.id }),
    beforeEnter: (to, from, next) => {
      store.dispatch('$_fingerbank/getCombination', to.params.id).then(() => {
        next()
      })
    }
  },
  {
    path: 'fingerbank/local/combination/:id/clone',
    name: 'cloneFingerbankCombination',
    component: TheView,
    props: (route) => ({ id: route.params.id, isClone: true }),
    beforeEnter: (to, from, next) => {
      store.dispatch('$_fingerbank/getCombination', to.params.id).then(() => {
        next()
      })
    }
  }
]
