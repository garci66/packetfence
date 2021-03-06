<template>
  <b-card no-body>
    <pf-config-list
      ref="pfConfigList"
      :config="config"
    >
      <template v-slot:pageHeader>
        <b-card-header>
          <b-row class="align-items-center px-0" no-gutters>
            <b-col cols="auto" class="mr-auto">
              <h4 class="d-inline mb-0" v-t="'DHCP Fingerprints'"></h4>
            </b-col>
            <b-col cols="auto" align="right" class="flex-grow-0">
              <b-button-group>
                <b-button v-t="'All'" :variant="(localScope === 'all') ? 'primary' : 'outline-secondary'" @click="changeScope('all')"></b-button>
                <b-button v-t="'Local'" :variant="(localScope === 'local') ? 'primary' : 'outline-secondary'" @click="changeScope('local')"></b-button>
                <b-button v-t="'Upstream'" :variant="(localScope === 'upstream') ? 'primary' : 'outline-secondary'" @click="changeScope('upstream')"></b-button>
              </b-button-group>
            </b-col>
          </b-row>
        </b-card-header>
      </template>
      <template v-slot:buttonAdd v-if="localScope === 'local'">
        <b-button variant="outline-primary" :to="{ name: 'newFingerbankDhcpFingerprint', params: { localScope: 'local' } }">{{ $t('New DHCP Fingerprint') }}</b-button>
      </template>
      <template v-slot:emptySearch="state">
        <pf-empty-table :isLoading="state.isLoading">{{ $t('No {localScope} DHCP fingerprints found', { localScope: ((localScope !== 'all') ? localScope : '') }) }}</pf-empty-table>
      </template>
      <template v-slot:cell(buttons)="item">
        <span class="float-right text-nowrap">
          <pf-button-delete size="sm" v-if="!item.not_deletable && localScope === 'local'" variant="outline-danger" class="mr-1" :disabled="isLoading" :confirm="$t('Delete DHCP Fingerprint?')" @on-delete="remove(item)" reverse/>
          <b-button size="sm" variant="outline-primary" class="mr-1" @click.stop.prevent="clone(item)">{{ $t('Clone') }}</b-button>
        </span>
      </template>
    </pf-config-list>
  </b-card>
</template>

<script>
import pfButtonDelete from '@/components/pfButtonDelete'
import pfConfigList from '@/components/pfConfigList'
import pfEmptyTable from '@/components/pfEmptyTable'
import { config } from '../_config/fingerbank/dhcpFingerprint'

export default {
  name: 'fingerbank-dhcp-fingerprints-list',
  components: {
    pfButtonDelete,
    pfConfigList,
    pfEmptyTable
  },
  props: {
    scope: {
      type: String,
      default: 'all'
    }
  },
  data () {
    return {
      data: [],
      config: config(this),
      localScope: this.scope
    }
  },
  methods: {
    clone (item) {
      this.$router.push({ name: 'cloneFingerbankDhcpFingerprint', params: { scope: 'local', id: item.id } })
    },
    remove (item) {
      this.$store.dispatch('$_fingerbank/deleteDhcpFingerprint', item.id).then(() => {
        const { $refs: { pfConfigList: { refreshList = () => {} } = {} } = {} } = this
        refreshList() // soft reload
      })
    },
    changeScope (scope) {
      this.localScope = scope
      this.config = config(this) // reset config
    }
  },
  created () {
    this.$store.dispatch('$_fingerbank/dhcpFingerprints').then(data => {
      this.data = data
    })
  },
  watch: {
    scope: {
      handler: function (a) {
        this.localScope = a
        this.config = config(this) // reset config
      }
    }
  }
}
</script>
