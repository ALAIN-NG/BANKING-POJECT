// Service pour les opérations notification
import api from './axiosConfig';

export const notificationService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/notification');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/notification/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/notification', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/notification/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/notification/' + id);
    return response.data;
  }
};
