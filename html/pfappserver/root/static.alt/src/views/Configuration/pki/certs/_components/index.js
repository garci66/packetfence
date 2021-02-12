import { BaseViewCollectionItem } from '../../../_components/new/'
import {
  BaseFormButtonBar,
  BaseFormGroupChosenCountry,
  BaseFormGroupInput
} from '@/components/new/'
import {
  BaseFormGroupChosenOneProfile
} from '../../_components/'
import ButtonCertificateDownload from './ButtonCertificateDownload'
import ButtonCertificateEmail from './ButtonCertificateEmail'
import ButtonCertificateRevoke from './ButtonCertificateRevoke'
import TheForm from './TheForm'
import TheView from './TheView'

export {
  BaseViewCollectionItem          as BaseView,
  BaseFormButtonBar               as FormButtonBar,

  BaseFormGroupInput              as FormGroupIdentifier,
  BaseFormGroupChosenOneProfile   as FormGroupProfileIdentifier,
  BaseFormGroupInput              as FormGroupCn,
  BaseFormGroupInput              as FormGroupMail,
  BaseFormGroupInput              as FormGroupOrganisation,
  BaseFormGroupChosenCountry      as FormGroupCountry,
  BaseFormGroupInput              as FormGroupState,
  BaseFormGroupInput              as FormGroupLocality,
  BaseFormGroupInput              as FormGroupStreetAddress,
  BaseFormGroupInput              as FormGroupPostalCode,

  ButtonCertificateDownload,
  ButtonCertificateEmail,
  ButtonCertificateRevoke,
  TheForm,
  TheView
}
