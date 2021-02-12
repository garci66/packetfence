import { computed, toRefs, unref } from '@vue/composition-api'
import useEventFnWrapper from '@/composables/useEventFnWrapper'
import { useInputMeta } from '@/composables/useMeta'
import { useOptionsPromise, useOptionsValue } from '@/composables/useInputMultiselect'
import { useInputValue } from '@/composables/useInputValue'
import BaseInputChosen, { props as BaseInputChosenProps } from './BaseInputChosen'

export const props = {
  ...BaseInputChosenProps,

  internalSearch: {
    type: Boolean,
    default: true
  }
}

export const setup = (props, context) => {

  const metaProps = useInputMeta(props, context)
  const {
    label,
    trackBy,
    options: optionsPromise,
    placeholder
  } = toRefs(metaProps)

  const options = useOptionsPromise(optionsPromise)

  const {
    value,
    onInput
  } = useInputValue(metaProps, context)

  const inputValueWrapper = computed(() => {
    const _value = unref(value)
    const _options = unref(options)
    const optionsIndex = _options.findIndex(option => option[unref(trackBy)] === _value)
    if (optionsIndex > -1) {
      return _options[optionsIndex]
    }
    else {
      return { [unref(label)]: _value, [unref(trackBy)]: _value }
    }
  })

  const inputPlaceholder = useOptionsValue(options, trackBy, label, placeholder)

  const onInputWrapper = useEventFnWrapper(onInput, value => {
    const { [unref(trackBy)]: trackedValue } = value
    return trackedValue
  })

  // clear single value
  const onRemove = () => onInput(null)

  const onTag = newValue => onInput(newValue)

  return {
    // wrappers
    inputValue: inputValueWrapper,
    onInput: onInputWrapper,
    inputPlaceholder,

    onRemove,
    onTag
  }
}

// @vue/component
export default {
  name: 'base-input-chosen-one',
  extends: BaseInputChosen,
  props,
  setup
}
