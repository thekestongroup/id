import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError, type Flow } from './api'
import { follow } from './session'

/**
 * For the sign-in pages: the app that's asking (from ?authRequestID), and
 * the server's view of where this page fits. If the server says another
 * page should be showing (e.g. already signed in), it goes there.
 */
export function useFlow(page: Flow['step']) {
  const route = useRoute()
  const router = useRouter()
  const authRequestID = computed(() => (route.query.authRequestID as string | undefined) || undefined)
  const flow = ref<Flow>()
  const error = ref<string>()
  /** Sign-in to the app was refused, but they may ask for it. */
  const refused = ref<{ clientId: string; clientName: string; pending: boolean }>()
  const loading = ref(true)

  onMounted(async () => {
    try {
      const f = await api.flow(authRequestID.value)
      flow.value = f
      // ?add=1: signing in to another account while already signed in.
      const adding = page === 'sign-in' && route.query.add !== undefined
      if (f.step !== page && !adding) {
        await follow(router, f, authRequestID.value)
      }
    } catch (e) {
      error.value = e instanceof ApiError ? e.message : 'Something went wrong. Try again.'
      if (e instanceof ApiError && e.code === 'app_refused' && e.data?.canRequest) {
        refused.value = { clientId: String(e.data.clientId), clientName: String(e.data.clientName), pending: !!e.data.pending }
      }
    } finally {
      loading.value = false
    }
  })

  /** After a step succeeds: on to the next one. */
  const next = (f: Flow) => follow(router, f, authRequestID.value)

  return { authRequestID, flow, client: computed(() => flow.value?.client), error, refused, loading, next }
}
