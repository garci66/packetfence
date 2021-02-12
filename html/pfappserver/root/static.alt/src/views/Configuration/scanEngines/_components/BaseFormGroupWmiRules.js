import {
  BaseFormGroupArrayDraggable, BaseFormGroupArrayDraggableProps,
  BaseInputChosenOne
} from '@/components/new'
import i18n from '@/utils/locale'

export const props = {
  ...BaseFormGroupArrayDraggableProps,

  buttonLabel: {
    type: String,
    default: i18n.t('Add WMI Rule')
  },
  // overload :childComponent
  childComponent: {
    type: Object,
    default: () => BaseInputChosenOne
  },
  // overload :defaultItem
  defaultItem: {
    type: String,
    default: null
  },
  // overload draggable handlers
  onAdd: {
    type: Function,
    default: (context, index, newComponent) => {
      const { doFocus = () => {} } = newComponent
      doFocus()
    }
  },
  striped: {
    type: Boolean,
    default: true
  }
}

export default {
  name: 'base-form-group-wmi-rules',
  extends: BaseFormGroupArrayDraggable,
  props
}
