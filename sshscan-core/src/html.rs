use std::collections::HashMap;

use build_html::{self, HtmlPage, Table, HtmlContainer, ContainerType, Container, Html, TableRow};

use crate::{agg_data::{self, AggregatedData}, Host};

const HOST_HEADER: &[&str; 5] = &[
    "Kex Algos",
    "Host Key Algos",
    "Encryption Algos",
    "MAC Algos",
    "Compression Algos",
];

const STYLE: &str = include_str!("style.css");

pub fn create_page() -> HtmlPage {
    let time = {
        use chrono::prelude::*;
        let time: DateTime<Local> = Local::now();
        time.format("%Y-%m-%d %H.%M UTC%z").to_string()
    };

    let page = HtmlPage::new()
    .with_title("report")
    .with_style(STYLE);
    
    page
    .with_meta([("date", time.as_str())])
    .with_meta([("generator", "https://github.com/AndrewPiroli/sshscan/")])
    .with_meta([("charset", "UTF-8")])
    .with_meta([("viewport", "width=device-width, initial-scale=1.0, user-scalable=yes")])
}

pub fn create_table_generic(header: &[&str], rows: &[Vec<String>]) -> Table {
    Table::from(rows)
    .with_attributes([("class", "sshscan-table")])
    .with_custom_header_row(TableRow::from(header).with_attributes([("class", "header-row")]))
}

pub fn create_host_table(host: &Host) -> Container {
    let mut c = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-outer")]);
    let data = agg_data::wrangle_host_to_table(host);
    for t in data {
        let id = format!("{}:{}", host.addr, t.0);
        let mut inner = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-inner"), ("id", id.as_str())]);
        inner.add_html(format!("<h3>{id}</h3>"));
        let tab = create_table_generic(HOST_HEADER, &t.1);
        inner.add_table(tab);
        c.add_container(inner);
    }
    c
}

pub fn generate(hosts: &[Host], agg_data: &AggregatedData) -> String {
    if hosts.len() < 1 { return create_page().to_html_string(); }
    let mut page = create_page();
    for host_table in hosts.iter().map(create_host_table) {
        page.add_container(host_table);
    }
    page.add_container(create_algo_list(HOST_HEADER[0], &agg_data.kex_algos));
    page.add_container(create_algo_list(HOST_HEADER[1], &agg_data.host_key_algos));
    page.add_container(create_algo_list(HOST_HEADER[2], &agg_data.encryption_algos));
    page.add_container(create_algo_list(HOST_HEADER[3], &agg_data.mac_algos));
    page.add_container(create_algo_list(HOST_HEADER[4], &agg_data.compression_algos));
    page.to_html_string()
}

pub fn create_algo_list(title: &str, list: &HashMap<String, Vec<&Host>>) -> Container {
    let mut c = Container::new(ContainerType::Div)
    .with_attributes([("class", "sshscan-alist-outer")])
    .with_html(format!("<h2>{title}</h2>"));
    for algo in list {
        let mut inner = Container::new(ContainerType::UnorderedList)
        .with_attributes([("class", "sshscan-alist-inner")]);
        for host in algo.1.iter() {
            for host_port in host.port_states.iter() {
                let id = format!("{}:{}", host.addr, host_port.portid);
                inner.add_link(format!("#{id}"), id.as_str());
            }
        }
        c.add_container(Container::new(ContainerType::Div).with_html(format!("<h3>{}</h3>", algo.0)).with_container(inner));
    }
    c
}