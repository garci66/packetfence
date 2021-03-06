<template>
  <div>
    <b-table :items="tableItems" :fields="tableFields" :sort-by="sortBy" :sort-desc="sortDesc"
      class="the-files-list"
      small hover striped show-empty no-local-sorting no-select-on-click borderless
      @sort-changed="onSortChanged($event)"
      @row-clicked="onRowClicked($event)"
    >
      <template v-slot:cell(name)="{ item }">
        <div v-if="item.type === 'dir'"
          variant="link"
          :disabled="false"
        >
          <navigation-icon v-for="(name, n) in item.icons" :key="n"
            :name="name" class="nav-icon"/>

          <icon v-if="item.expand"
            name="regular/folder-open"/>
          <icon v-else
            name="regular/folder"/> {{ item.name }}
        </div>
        <div v-else
          variant="link"
        >
          <navigation-icon v-for="(name, n) in item.icons" :key="n"
            :name="name" class="nav-icon"/>

          <icon name="file" v-if="!item.not_revertible || !item.not_deletable"/>
          <icon name="regular/file" v-else/>
          {{ item.name }}
        </div>
      </template>
      <template v-slot:cell(buttons)="{ item }">
        <div v-if="item.type === 'file'"
          class="text-right text-nowrap">

          <base-button-confirm v-if="!item.not_deletable"
            size="sm" variant="outline-danger" class="my-1 mr-1"
            :disabled="isLoading"
            :confirm="$t('Delete?')"
            reverse
            @click="onDelete(item)"
          >{{ $t('Delete') }}</base-button-confirm>

          <base-button-confirm v-else-if="!item.not_revertible"
            size="sm" variant="outline-danger" class="my-1 mr-1"
            :disabled="isLoading"
            :confirm="$t('Revert?')"
            reverse
            @click="onDelete(item)"
          >{{ $t('Revert') }}</base-button-confirm>

          <b-button v-if="previewUrl"
            size="sm" variant="outline-secondary" class="my-1"
            :href="previewUrl(item)" target="_blank"
          >{{ $t('Preview') }} <icon class="ml-1" name="external-link-alt"></icon></b-button>
        </div>
        <div v-else-if="item.type === 'dir'"
          class="text-right text-nowrap">

          <b-dropdown :text="$i18n.t('Create')"
            size="sm" variant="outline-primary" class="my-1" right>
            <b-dropdown-item @click="onToggleDirectory(item)">New Sub Directory</b-dropdown-item>
            <b-dropdown-item @click="onToggleFile(item)">New File</b-dropdown-item>
          </b-dropdown>

        </div>
      </template>
    </b-table>

    <modal-directory
      v-model="isShowDirectoryModal"
      :entries="entries"
      :id="id"
      :path="lastPath"
      @create="onCreateDirectory($event)"
      @hidden="onToggleDirectory"
    />

    <modal-file
      v-model="isShowFileModal"
      :entries="entries"
      :id="id"
      :path="lastPath"
      @create="onCreateFile($event)"
      @update="onUpdateFile($event)"
      @delete="onDeleteFile($event)"
      @hidden="onToggleFile"
    />

  </div>
</template>
<script>
import NavigationIcon from 'vue-awesome/components/Icon'
NavigationIcon.register({
  pass: {
    width: 100,
    height: 100,
    d: 'M 47.5 0 H 52.5 V 100 H 47.5 L 47.5 0'
  },
  node: {
    width: 100,
    height: 100,
    d: 'M 47.5 0 H 52.5 V 47.5 H 100 V 52.5 H 52.5 V 100 H 47.5 L 47.5 0'
  },
  last: {
    width: 100,
    height: 100,
    d: 'M 47.5 0 H 52.5 V 47.5 H 100 V 52.5 H 47.5 L 47.5 0'
  },
  skip: {
    width: 100,
    height: 100,
    d: ''
  }
})

import {
  BaseButtonConfirm,
} from '@/components/new/'
import {
  ModalDirectory,
  ModalFile
} from './'

const components = {
  BaseButtonConfirm,
  NavigationIcon,
  ModalDirectory,
  ModalFile
}

const props = {
  id: {
    type: String
  }
}

import { pfFormatters } from '@/globals/pfFormatters'

const tableFields = [
  {
    key: 'name',
    label: 'Name', // i18n defer
    class: 'w-50 text-nowrap',
    required: true,
    sortable: true
  },
  {
    key: 'size',
    label: 'Size', // i18n defer
    formatter: pfFormatters.fileSize,
    tdClass: 'text-right text-nowrap',
    thClass: 'text-right text-nowrap',
    sortable: true
  },
  {
    key: 'mtime',
    label: 'Last modification', // i18n defer
    formatter: pfFormatters.shortDateTime,
    tdClass: 'text-right text-nowrap',
    thClass: 'text-right text-nowrap',
    sortable: true
  },
  {
    key: 'buttons',
    label: '',
    locked: true
  }
]

import { computed, ref, toRefs, watch } from '@vue/composition-api'

const setup = (props, context) => {

  const {
    id
  } = toRefs(props)

  const { root: { $store } = {} } = context

  const sortBy = ref(undefined)
  const sortDesc = ref(false)
  const entries = ref([])

  const expandPaths = ref([])
  const expandPath = (path) => {
    expandPaths.value = [ ...expandPaths.value, path ]
  }
  const collapsePath = (path) => {
    expandPaths.value = expandPaths.value.filter(_path => {
      if (_path.indexOf(path) !== 0)
        return _path
    })
  }

  const tableItems = ref([])
  const isLoading = computed(() => $store.getters['$_connection_profiles/isLoadingFiles'])

  const _getFiles = () => {
    let sort = ['type']
    if (sortBy.value) {
      let _sortBy = sortDesc.value ? `${sortBy.value} DESC` : sortBy.value
      sort.push(_sortBy)
    }
    else
      sort.push('name')
    $store.dispatch('$_connection_profiles/files', { id: id.value, sort }).then(response => {
      entries.value = JSON.parse(JSON.stringify(response.entries))
    })
  }

  watch([sortBy, sortDesc], () => _getFiles(), { immediate: true })

  watch([entries, expandPaths], () => {
    const reduceEntries = (entries, path = '', _icons = []) => {
      return entries.reduce((reduced, entry, e) => {
        const last = (e === entries.length - 1)
        const icons = [ ..._icons, (last) ? 'last' : 'node' ]
        const { entries: childEntries = [], ...rest } = entry || {}
        const { type, name } = rest || {}
        const fullPath = `${path}/${name}`
        switch(type) {
          case 'dir':
            if (expandPaths.value.includes(fullPath)) {
              reduced.push({ ...rest, path, expand: true, icons })
              reduced.push(...reduceEntries(childEntries, fullPath, [ ..._icons, (last) ? 'skip' : 'pass' ]))
            }
            else
              reduced.push({ ...rest, path, expand: false, icons })
            break
          case 'file':
            reduced.push({ ...rest, path, icons })
            break
        }
        return reduced
      }, [])
    }
    tableItems.value = reduceEntries(entries.value)
  }, { deep: true })

  const onSortChanged = (params) => {
    sortBy.value = params.sortBy
    sortDesc.value = params.sortDesc
  }

  const onRowClicked = (row) => {
    const { path, name, type } = row || {}
    const fullPath = `${path}/${name}`
    if (type === 'dir') {
      if (expandPaths.value.includes(fullPath))
        collapsePath(fullPath)
      else
        expandPath(fullPath)
    }
    else if (type === 'file') {
      onToggleFile(row)
    }
  }

  const onDelete = (item) => {
    const { path, name } = item
    $store.dispatch('$_connection_profiles/deleteFile', { id: id.value, filename: `${path}/${name}` }).then(response => {
      entries.value = JSON.parse(JSON.stringify(response.entries))
    })
  }

  const previewUrl = (item) => {
    let path = ['/config/profile', id.value, 'preview']
    if (item.path)
      path.push(...item.path.split('/').filter(u => u))
    path.push(item.name)
    return path.join('/')
  }

  const lastPath = ref(undefined)
  const isShowDirectoryModal = ref(false)
  const onToggleDirectory = (item) => {
    lastPath.value = `${item.path}/${item.name}`
    isShowDirectoryModal.value = !isShowDirectoryModal.value
  }

  const isShowFileModal = ref(false)
  const onToggleFile = (item) => {
    lastPath.value = `${item.path}/${item.name}`
    isShowFileModal.value = !isShowFileModal.value
  }

  const onCreateDirectory = (name) => {
    let _entries = entries.value
    let parts = lastPath.value.split('/').filter(p => p)
    // traverse tree using path parts
    while (parts.length > 0) {
      for (let e = 0; e < _entries.length; e++) {
        const { name, entries: childEntries = [] } = _entries[e]
        if (name === parts[0]) {
          _entries = childEntries
          break
        }
      }
      parts = parts.slice(1)
    }
    _entries.push({ type: 'dir', name, size: 0, mtime: 0, entries: [] })
    expandPath(lastPath.value)
  }

  const onCreateFile = (path) => {
    lastPath.value = path
    expandPath(lastPath.value)
    _getFiles()
  }

  const onUpdateFile = () => _getFiles()

  const onDeleteFile = () => {
    isShowFileModal.value = false
    _getFiles()
  }

  return {
    sortBy,
    sortDesc,
    entries,
    expandPaths,
    tableFields,
    tableItems,
    isLoading,
    onDelete,
    onSortChanged,
    onRowClicked,
    previewUrl,

    isShowDirectoryModal,
    onCreateDirectory,
    onToggleDirectory,

    isShowFileModal,
    onCreateFile,
    onUpdateFile,
    onDeleteFile,
    onToggleFile,

    lastPath
  }
}

// @vue/component
export default {
  name: 'the-files-list',
  inheritAttrs: false,
  components,
  props,
  setup
}
</script>
<style lang="scss">
.the-files-list {
  thead[role="rowgroup"] {
    border-bottom: 1px solid #dee2e6 !important;
  }
  tr[role="row"],
  tr[role="row"] > th[role="columnheader"] {
    cursor: pointer;
    outline-width: 0;
    td[role="cell"] {
      padding: 0 0.3rem;
      text-wrap: nowrap;
      div[variant="link"] {
        line-height: 1em;
      }
    }
    td[aria-colindex="1"] {
      svg.fa-icon:not(.nav-icon) {
        margin: 0.25rem 0;
        min-width: 36px;
        height: auto;
        max-height: 18px;
      }
      svg.nav-icon {
        color: $gray-500;
        height: 36px;
      }
    }
  }
}
</style>
