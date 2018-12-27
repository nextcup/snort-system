from django.contrib import admin
from panel import models

# Register your models here.


class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'password')
    ordering = ["id", ]


class RulesAdmin(admin.ModelAdmin):
    list_display = ('id', 'sid', 'msg', 'reference', 'class_type', 'malname',
                    'attacker', 'victim', 'success_attack', 'controller',
                    'confirm_controlled', 'rev', 'knowledge_base',
                    'create_time', 'update_time', 'shield', 'contain',
                    'first_check_time', 'first_check_position',
                    'overall_first_check_time', 'overall_first_check_position',
                    'check_out_numbers', 'error_numbers', 'feature_source',
                    'remarks', 'is_translate', 'content', 'has_conflict'
                    )
    ordering = ["id", ]


class CompleteRuleAdmin(admin.ModelAdmin):
    list_display = ('sid', 'rule')
    ordering = ["sid", ]


class LogAdmin(admin.ModelAdmin):
    list_display = ('sid', 'action', 'time', 'person', 'status', 'msg', 'ip')
    ordering = ["sid", ]


class UpdateAdmin(admin.ModelAdmin):
    list_display = ('sid', 'rule')
    ordering = ["sid", ]


class RulePcapAdmin(admin.ModelAdmin):
    list_display = ('sid', 'pcap')
    ordering = ["sid", ]


admin.site.register(models.Rule, RulesAdmin)
admin.site.register(models.User, UserAdmin)
admin.site.register(models.CompleteRule, CompleteRuleAdmin)
admin.site.register(models.Log, LogAdmin)
admin.site.register(models.UpdateRule, UpdateAdmin)
admin.site.register(models.RulePcap, RulePcapAdmin)
