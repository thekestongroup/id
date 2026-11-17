import { ref } from 'vue'
import { api, type Guest } from './api'

/**
 * Guest invitations waiting for the signed-in person (with whether their
 * one-time pop-up has been shown), shared by the account pages' layout and
 * the Overview card.
 */
export const invitations = ref<(Guest & { popup: boolean })[]>([])

export async function loadInvitations() {
  const p = await api.prompts().catch(() => undefined)
  if (p) invitations.value = p.guestInvitations
}
