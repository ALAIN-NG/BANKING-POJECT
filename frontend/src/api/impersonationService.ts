// Service pour les opérations impersonation
import api from './axiosConfig';

export const impersonationService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/impersonation');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/impersonation/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/impersonation', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/impersonation/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/impersonation/' + id);
    return response.data;
  }
};
