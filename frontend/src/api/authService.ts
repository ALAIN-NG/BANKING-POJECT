// Service pour les opérations auth
import api from './axiosConfig';

export const authService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/auth');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/auth/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/auth', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/auth/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/auth/' + id);
    return response.data;
  }
};
