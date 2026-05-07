/**
 * Route table — one entry per primary view in the application shell.
 */

import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'vaults',
    component: () => import('@/views/VaultsView.vue'),
  },
  {
    path: '/targets',
    name: 'targets',
    component: () => import('@/views/TargetsView.vue'),
  },
  {
    path: '/findings',
    name: 'findings',
    component: () => import('@/views/FindingsView.vue'),
  },
  {
    path: '/scans',
    name: 'scans',
    component: () => import('@/views/ScansView.vue'),
  },
  {
    path: '/signatures',
    name: 'signatures',
    component: () => import('@/views/SignaturesView.vue'),
  },
  {
    path: '/proxy',
    name: 'proxy',
    component: () => import('@/views/ProxyView.vue'),
  },
  {
    path: '/workflows',
    name: 'workflows',
    component: () => import('@/views/PlaceholderView.vue'),
    props: {
      title: 'No workflows yet',
      hint: 'Chain signatures into reusable scan recipes. Workflows run multiple signatures in sequence and roll up results.',
      actionLabel: 'New workflow',
      actionKind: 'workflow',
    },
  },
  {
    path: '/notes',
    name: 'notes',
    component: () => import('@/views/PlaceholderView.vue'),
    props: {
      title: 'Notes',
      hint: 'Plain-text notes alongside your engagement. Markdown supported.',
      actionLabel: 'New note',
      actionKind: 'note',
    },
  },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

export default router
