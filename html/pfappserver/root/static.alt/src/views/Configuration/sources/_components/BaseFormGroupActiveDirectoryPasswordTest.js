import { BaseFormGroupInputPasswordTest, BaseFormGroupInputPasswordTestProps } from '@/components/new/'
import store from '@/store'
import i18n from '@/utils/locale'

export const props = {
  ...BaseFormGroupInputPasswordTestProps,

  test: {
    type: Function,
    default: (value, form) => store.dispatch('$_sources/testAuthenticationSource', form)
      .then(() => {
        return i18n.t('Successfully validated with {host}.', form)
      })
      .catch(err => {
        const { response: { data: { message } = {} } = {} } = err
        if (message)
          throw message
      })
  },
  testLabel: {
    type: String,
    default: i18n.t('Validating...')
  }
}

export default {
  name: 'base-form-group-active-directory-password-test',
  extends: BaseFormGroupInputPasswordTest,
  props
}


