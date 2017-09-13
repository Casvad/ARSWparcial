/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT = 5;
    private static AtomicInteger checkedListsCount = new AtomicInteger(0);
    private static AtomicInteger hilosVivos = new AtomicInteger(Runtime.getRuntime().availableProcessors());
    private static LinkedList<Integer> blackListOcurrences = new LinkedList<>();
    private static boolean yaTermine = false;

    /**
     * Check the given host's IP address in all the available black lists, and
     * report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case. The
     * search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as NOT
     * Trustworthy, and the list of the five blacklists returned.
     *
     * @param ipaddress suspicious host's IP address.
     * @return Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress) {
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        int n = skds.getRegisteredServersCount();
        int procesadores = Runtime.getRuntime().availableProcessors();
        int diviciones = n / procesadores;
        SecurityThread[] st = new SecurityThread[procesadores];

        for (int i = 0; i < st.length; i++) {
            if (i != st.length - 1) {
                st[i] = new SecurityThread(i * diviciones, diviciones * (i + 1), ipaddress); //tiene los maximos posibles
            } else {
                st[i] = new SecurityThread(i * diviciones, n, ipaddress);//es el ultimo, solo toma los elmeentos restastes
            }
        }
        for (int i = 0; i < st.length; i++) {
            st[i].start();
        }
        synchronized (LockPrincipal.getLock()) {
            try {
                LockPrincipal.getLock().wait();

            } catch (InterruptedException ex) {
            }
        }

        if (blackListOcurrences.size() >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ipaddress);
        } else {
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});

        return blackListOcurrences;
    }

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    /**
     * agrega un elemento a la lista
     * @param elem el elemento a agregar
     */
    public static synchronized void agregarElemento(int elem) {
        blackListOcurrences.add(elem);
        if (blackListOcurrences.size() >= BLACK_LIST_ALARM_COUNT) {
            yaTermine = true;
            synchronized (LockPrincipal.getLock()) {
                LockPrincipal.getLock().notify();

            }
        }
    }
    
    /**
     * aumenta la cuenta de las listas que ya ha revisado
     */
    public static void agregarElementoRevisado(){
        checkedListsCount.addAndGet(1);
    }
    
    /**
     * Revisa si es el ultimo hilo (sin contar el principal)
     * @return true, si es el ultimo hilo vivo, false de lo contrario
     */
    static synchronized boolean soyElUltimo() {
        if(hilosVivos.addAndGet(-1)==0){
            yaTermine = true;
            synchronized (LockPrincipal.getLock()) {
                LockPrincipal.getLock().notify();
            }
        }
        
        return yaTermine;
    }

    /**
     * @return the yaTermine
     */
    public static boolean isYaTermine() {
        return yaTermine;
    }

}
