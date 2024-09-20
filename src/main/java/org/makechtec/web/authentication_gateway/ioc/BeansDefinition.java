package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.ioc.BeanInformation;

import java.util.HashSet;
import java.util.Set;

public class BeansDefinition {

    public static Set<BeanInformation> beans() {
        var beans = new HashSet<BeanInformation>();

        beans.addAll(FiltersDefinition.beans());
        beans.addAll(ActionsDefinition.beans());
        beans.addAll(HandlersDefinition.beans());

        return beans;
    }

}
