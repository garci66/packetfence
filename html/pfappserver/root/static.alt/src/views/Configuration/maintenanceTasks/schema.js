import store from '@/store'
import i18n from '@/utils/locale'
import yup from '@/utils/yup'

yup.addMethod(yup.string, 'maintenanceTaskIdNotExistsExcept', function (exceptId = '', message) {
  return this.test({
    name: 'maintenanceTaskIdNotExistsExcept',
    message: message || i18n.t('Name exists.'),
    test: (value) => {
      if (!value || value.toLowerCase() === exceptId.toLowerCase()) return true
      return store.dispatch('config/getMaintenanceTasks').then(response => {
        return response.filter(maintenanceTask => maintenanceTask.id.toLowerCase() === value.toLowerCase()).length === 0
      }).catch(() => {
        return true
      })
    }
  })
})

export default (props) => {
  const {
    id,
    isNew,
    isClone
  } = props

  return yup.object().shape({
    id: yup.string()
      .nullable()
      .required(i18n.t('Name required.'))
      .maintenanceTaskIdNotExistsExcept((!isNew && !isClone) ? id : undefined, i18n.t('Name exists.'))
  })
}

export { yup }
