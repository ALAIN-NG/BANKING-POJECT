// Service pour les opérations account
import api from './axiosConfig';

export const accountService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/account');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/account/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/account', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/account/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/account/' + id);
    return response.data;
  }
};
