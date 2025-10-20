// Service pour les opérations security
import api from './axiosConfig';

export const securityService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/security');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/security/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/security', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/security/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/security/' + id);
    return response.data;
  }
};
