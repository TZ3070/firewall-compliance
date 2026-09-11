import { createRouter, createWebHistory } from 'vue-router'

import ComplianceWorkspace from './views/ComplianceWorkspace.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'compliance-workspace',
      component: ComplianceWorkspace,
    },
  ],
})
