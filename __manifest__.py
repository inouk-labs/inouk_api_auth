{
    'name': "Inouk API Auth",

    'summary': "Allows to protect Custom API with Hawk Token ",
    'description': """
        Requires: mohawk==1.1.0
    """,
    'author': "@cmorisse",
    'website': "https://fr.linkedin.com/in/cyrilmorisse",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/12.0/odoo/addons/base/data/ir_module_category_data.xml
    # for the full list
    'category': 'Uncategorized',
    'version': '0.1',

    # any module necessary for this one to work correctly
    'depends': [
        'inouk_core',
    ],

    # always loaded
    'data': [
        # Security
        'security/ir.model.access.csv',

        # data
        #'data/delivery_mode.xml',
        
        # Views
        'views/api_auth_token_views.xml',

        # Menus
        'menu.xml',
    ],
    # only loaded in demonstration mode
    'demo': [
        #'demo/demo.xml',
    ],
    'license': 'OPL-1',
    'post_load': 'install_monkey_patches',
    'application': False,
    'auto_install': False,
    'installable': True
}